/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.android.tools.apk.analyzer;

import com.android.SdkConstants;
import com.android.annotations.NonNull;
import com.android.annotations.Nullable;
import com.android.ide.common.process.ProcessException;
import com.android.ide.common.xml.AndroidManifestParser;
import com.android.ide.common.xml.ManifestData;
import com.android.sdklib.repository.AndroidSdkHandler;
import com.android.tools.apk.analyzer.dex.DexDisassembler;
import com.android.tools.apk.analyzer.dex.DexFileStats;
import com.android.tools.apk.analyzer.dex.DexFiles;
import com.android.tools.apk.analyzer.internal.ApkDiffEntry;
import com.android.tools.apk.analyzer.internal.ApkDiffParser;
import com.android.tools.apk.analyzer.internal.ApkFileByFileDiffParser;
import com.android.tools.apk.analyzer.internal.SigUtils;
import com.android.utils.NullLogger;
import com.google.common.collect.ImmutableList;
import com.google.devrel.gmscore.tools.apk.arsc.*;
import io.reactivex.Observable;
import io.reactivex.ObservableEmitter;
import org.jf.dexlib2.dexbacked.DexBackedClassDef;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.xml.sax.SAXException;

import javax.swing.tree.DefaultMutableTreeNode;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Tool for getting all kinds of information about an APK, including: - basic package info, sizes
 * and files list - dex code - resources
 */
public class ApkAnalyzer {

    private static final String ANDROID_HOME_SDK = "ANDROID_HOME";

    @NonNull
    private final AaptInvoker aaptInvoker;
    private boolean humanReadableFlag;
    private Path apkPath;

    private Archive archive;

    public ApkAnalyzer(Path apk) throws IOException {
        this(apk, null);
    }

    public ApkAnalyzer(Path apk, @Nullable String osSdkFolder) throws IOException {
        this.aaptInvoker = getAaptInvokerFromSdk(null);
        archive = Archives.open(apk);
        apkPath = apk;
    }

    private static String getAndroidSdkFolder() {
        String sdkFolder = System.getenv(ANDROID_HOME_SDK);
        if (sdkFolder == null) {
            throw new RuntimeException("android sdk not set \"export ANDROID_HOME=$HOME/Library/Android/sdk\"");
        }
        return sdkFolder;
    }

    private static AaptInvoker getAaptInvokerFromSdk(@Nullable String osSdkFolder) {
        if (osSdkFolder == null) {
            osSdkFolder = getAndroidSdkFolder();
        }
        AndroidSdkHandler sdkHandler = AndroidSdkHandler.getInstance(new File(osSdkFolder));
        return new AaptInvoker(sdkHandler, new NullLogger());
    }

    @NonNull
    private static String getHumanizedSize(long sizeInBytes) {
        long kilo = 1024;
        long mega = kilo * kilo;

        DecimalFormat formatter = new DecimalFormat("#.#");
        int sign = sizeInBytes < 0 ? -1 : 1;
        sizeInBytes = Math.abs(sizeInBytes);
        if (sizeInBytes > mega) {
            return formatter.format((sign * sizeInBytes) / (double) mega) + "MB";
        } else if (sizeInBytes > kilo) {
            return formatter.format((sign * sizeInBytes) / (double) kilo) + "KB";
        } else {
            return (sign * sizeInBytes) + "B";
        }
    }

    @NonNull
    private static String formatValue(
            @NonNull BinaryResourceValue value, @NonNull StringPoolChunk stringPoolChunk) {
        if (value.type() == BinaryResourceValue.Type.STRING) {
            return stringPoolChunk.getString(value.data());
        }
        return BinaryXmlParser.formatValue(value, stringPoolChunk);
    }

    @NonNull
    private static List<Path> getDexFilesFrom(Path dir) {
        try (Stream<Path> stream = Files.list(dir)) {
            return stream.filter(
                    path ->
                            Files.isRegularFile(path)
                                    && path.getFileName()
                                    .toString()
                                    .endsWith(".dex"))
                    .collect(Collectors.toList());
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static int getResId(int packId, int resTypeId, int entryId) {
        return (((packId) << 24) | (((resTypeId) & 0xFF) << 16) | (entryId & 0xFFFF));
    }

    /**
     * close the archive
     *
     * @throws IOException
     */
    public void close() throws IOException {
        archive.close();
    }

    /**
     * get packages name
     *
     * @return Observable
     */
    public Observable<String> resPackages() {
        return Observable.create(emitter -> {

            byte[] resContents =
                    Files.readAllBytes(archive.getContentRoot().resolve("resources.arsc"));
            BinaryResourceFile binaryRes = new BinaryResourceFile(resContents);
            List<Chunk> chunks = binaryRes.getChunks();
            if (chunks.isEmpty()) {
                throw new IOException("no chunks");
            }

            if (!(chunks.get(0) instanceof ResourceTableChunk)) {
                throw new IOException("no res table chunk");
            }

            ResourceTableChunk resourceTableChunk = (ResourceTableChunk) chunks.get(0);
            resourceTableChunk
                    .getPackages()
                    .forEach(packageChunk -> emitter.onNext(packageChunk.getPackageName()));

            emitter.onComplete();
        });
    }

    /**
     * get binary xml file content
     *
     * @param filePath xml file path
     * @return String
     * @throws IOException The supplied file is not a binary XML resource.
     */
    public String resXml(@NonNull String filePath) throws IOException {
        Path path = archive.getContentRoot().resolve(filePath);
        byte[] bytes = Files.readAllBytes(path);
        if (!archive.isBinaryXml(path, bytes)) {
            throw new IOException("The supplied file is not a binary XML resource.");
        }
        return new String(BinaryXmlParser.decodeXml(path.getFileName().toString(), bytes));
    }

    /**
     * get all resource name of the specified resource type and resource config
     *
     * @param type        [string/dimen/color/...]
     * @param config      [default/v22/v26/en/zh-rCN/hdpi/...]
     * @param packageName [null to find first package or find the specified the package name]
     * @return Observable
     */
    public Observable<String> resNames(
            @NonNull String type,
            @NonNull String config,
            @Nullable String packageName) {

        return Observable.create(emitter -> {

            byte[] resContents =
                    Files.readAllBytes(archive.getContentRoot().resolve("resources.arsc"));
            BinaryResourceFile binaryRes = new BinaryResourceFile(resContents);
            List<Chunk> chunks = binaryRes.getChunks();
            if (chunks.isEmpty()) {
                throw new IOException("no chunks");
            }

            if (!(chunks.get(0) instanceof ResourceTableChunk)) {
                throw new IOException("no res table chunk");
            }

            ResourceTableChunk resourceTableChunk = (ResourceTableChunk) chunks.get(0);
            Optional<PackageChunk> packageChunk;
            if (packageName != null) {
                packageChunk = Optional.ofNullable(resourceTableChunk.getPackage(packageName));
            } else {
                packageChunk = resourceTableChunk.getPackages().stream().findFirst();
            }
            if (!packageChunk.isPresent()) {
                throw new IllegalArgumentException(
                        String.format(
                                "Can't find package chunk %s",
                                packageName == null ? "" : "(" + packageName + ")"));
            }
            TypeSpecChunk typeSpecChunk = packageChunk.get().getTypeSpecChunk(type);
            List<TypeChunk> typeChunks =
                    ImmutableList.copyOf(packageChunk.get().getTypeChunks(typeSpecChunk.getId()));
            for (TypeChunk typeChunk : typeChunks) {
                if (config.equals(typeChunk.getConfiguration().toString())) {
                    for (TypeChunk.Entry typeEntry : typeChunk.getEntries().values()) {
                        emitter.onNext(typeEntry.key());
                    }
                    emitter.onComplete();
                    return;
                }
            }

            throw new IllegalArgumentException(
                    String.format("Can't find specified resource configuration (%s)", config));
        });
    }

    /**
     * get resource value of the specified resource name
     *
     * @param type        [string/dimen/color/...]
     * @param config      [default/v22/v26/en/zh-rCN/hdpi/...]
     * @param name        the resource name
     * @param packageName [null to find first package or find the specified the package name]
     * @return Observable
     */
    public Observable<String> resValue(
            @NonNull String type,
            @NonNull String config,
            @NonNull String name,
            @Nullable String packageName) {

        return Observable.create(emitter -> {

            byte[] resContents =
                    Files.readAllBytes(archive.getContentRoot().resolve("resources.arsc"));
            BinaryResourceFile binaryRes = new BinaryResourceFile(resContents);
            List<Chunk> chunks = binaryRes.getChunks();
            if (chunks.isEmpty()) {
                throw new IOException("no chunks");
            }

            if (!(chunks.get(0) instanceof ResourceTableChunk)) {
                throw new IOException("no res table chunk");
            }

            ResourceTableChunk resourceTableChunk = (ResourceTableChunk) chunks.get(0);
            StringPoolChunk stringPoolChunk = resourceTableChunk.getStringPool();
            Optional<PackageChunk> packageChunk;
            if (packageName != null) {
                packageChunk = Optional.ofNullable(resourceTableChunk.getPackage(packageName));
            } else {
                packageChunk = resourceTableChunk.getPackages().stream().findFirst();
            }
            if (!packageChunk.isPresent()) {
                throw new IllegalArgumentException(
                        String.format(
                                "Can't find package chunk %s",
                                packageName == null ? "" : "(" + packageName + ")"));
            }
            TypeSpecChunk typeSpecChunk = packageChunk.get().getTypeSpecChunk(type);
            List<TypeChunk> typeChunks =
                    ImmutableList.copyOf(packageChunk.get().getTypeChunks(typeSpecChunk.getId()));
            for (TypeChunk typeChunk : typeChunks) {
                if (config.equals(typeChunk.getConfiguration().toString())) {
                    for (TypeChunk.Entry typeEntry : typeChunk.getEntries().values()) {
                        if (name.equals(typeEntry.key())) {
                            BinaryResourceValue value = typeEntry.value();
                            String valueString = null;
                            if (value != null) {
                                valueString = formatValue(value, stringPoolChunk);
                            } else {
                                Map<Integer, BinaryResourceValue> values = typeEntry.values();
                                if (values != null) {
                                    valueString =
                                            values.values()
                                                    .stream()
                                                    .map(v -> formatValue(v, stringPoolChunk))
                                                    .collect(Collectors.joining(", "));
                                }
                            }
                            if (valueString != null) {
                                emitter.onNext(valueString);
                            } else {
                                throw new IllegalArgumentException(
                                        "Can't find specified resource value");
                            }
                        }
                    }
                    emitter.onComplete();
                    return;
                }
            }
            throw new IllegalArgumentException(
                    String.format("Can't find specified resource configuration (%s)", config));
        });
    }

    /**
     * get resource ID of the specified resource name
     *
     * @param type        [string/dimen/color/...]
     * @param config      [default/v22/v26/en/zh-rCN/hdpi/...]
     * @param name        the resource name
     * @param packageName [null to find first package or find the specified the package name]
     * @return Observable
     */
    public Observable<String> resId(
            @NonNull String type,
            @NonNull String config,
            @NonNull String name,
            @Nullable String packageName) {
        return Observable.create(emitter -> {
            byte[] resContents =
                    Files.readAllBytes(archive.getContentRoot().resolve("resources.arsc"));
            BinaryResourceFile binaryRes = new BinaryResourceFile(resContents);
            List<Chunk> chunks = binaryRes.getChunks();
            if (chunks.isEmpty()) {
                throw new IOException("no chunks");
            }

            if (!(chunks.get(0) instanceof ResourceTableChunk)) {
                throw new IOException("no res table chunk");
            }

            ResourceTableChunk resourceTableChunk = (ResourceTableChunk) chunks.get(0);
            Optional<PackageChunk> packageChunk;
            if (packageName != null) {
                packageChunk = Optional.ofNullable(resourceTableChunk.getPackage(packageName));
            } else {
                packageChunk = resourceTableChunk.getPackages().stream().findFirst();
            }
            if (!packageChunk.isPresent()) {
                throw new IllegalArgumentException(
                        String.format(
                                "Can't find package chunk %s",
                                packageName == null ? "" : "(" + packageName + ")"));
            }
            int packageId = packageChunk.get().getId();

            TypeSpecChunk typeSpecChunk = packageChunk.get().getTypeSpecChunk(type);
            int resTypeId = typeSpecChunk.getId();
            List<TypeChunk> typeChunks =
                    ImmutableList.copyOf(packageChunk.get().getTypeChunks(typeSpecChunk.getId()));
            for (TypeChunk typeChunk : typeChunks) {
                if (config.equals(typeChunk.getConfiguration().toString())) {
                    for (Map.Entry<Integer, TypeChunk.Entry> entry : typeChunk.getEntries().entrySet()) {
                        if (name.equals(entry.getValue().key())) {
                            int entryId = entry.getKey();
                            int resId = getResId(packageId, resTypeId, entryId);
                            emitter.onNext("0x" + Integer.toHexString(resId));
                        }
                    }
                    emitter.onComplete();
                    return;
                }
            }
            throw new IllegalArgumentException(
                    String.format("Can't find specified resource configuration (%s)", config));
        });
    }

    /**
     * get all resource configs of the specified resource type
     *
     * @param type        [string/dimen/color/...]
     * @param packageName [null to find first package or find the specified the package name]
     * @return Observable
     */
    public Observable<String> resConfigs(@NonNull String type, @Nullable String packageName) {
        return Observable.create(emitter -> {

            byte[] resContents =
                    Files.readAllBytes(archive.getContentRoot().resolve("resources.arsc"));
            BinaryResourceFile binaryRes = new BinaryResourceFile(resContents);
            List<Chunk> chunks = binaryRes.getChunks();
            if (chunks.isEmpty()) {
                throw new IOException("no chunks");
            }

            if (!(chunks.get(0) instanceof ResourceTableChunk)) {
                throw new IOException("no res table chunk");
            }

            ResourceTableChunk resourceTableChunk = (ResourceTableChunk) chunks.get(0);
            Optional<PackageChunk> packageChunk;
            if (packageName != null) {
                packageChunk = Optional.ofNullable(resourceTableChunk.getPackage(packageName));
            } else {
                packageChunk = resourceTableChunk.getPackages().stream().findFirst();
            }
            if (!packageChunk.isPresent()) {
                throw new IllegalArgumentException(
                        String.format(
                                "Can't find package chunk %s",
                                packageName == null ? "" : "(" + packageName + ")"));
            }
            TypeSpecChunk typeSpecChunk = packageChunk.get().getTypeSpecChunk(type);
            List<TypeChunk> typeChunks =
                    ImmutableList.copyOf(packageChunk.get().getTypeChunks(typeSpecChunk.getId()));
            for (TypeChunk typeChunk : typeChunks) {
                emitter.onNext(typeChunk.getConfiguration().toString());
            }
            emitter.onComplete();

        });
    }

    /**
     * get dex code of the specified class and method
     *
     * @param fqcn   full qualified class name e.g. "android.app.ContextImpl"
     * @param method method name e.g. "onStart()V"
     * @return Observable
     */
    public Observable<String> dexCode(@NonNull String fqcn, @Nullable final String method) {
        return Observable.create(emitter -> {
            String newMethod = method;
            Collection<Path> dexPaths = getDexFilesFrom(archive.getContentRoot());

            boolean dexFound = false;
            for (Path dexPath : dexPaths) {
                DexBackedDexFile dexBackedDexFile = DexFiles.getDexFile(dexPath);
                DexDisassembler disassembler = new DexDisassembler(dexBackedDexFile);
                if (method == null) {
                    try {
                        emitter.onNext(disassembler.disassembleClass(fqcn));
                        dexFound = true;
                    } catch (IllegalStateException e) {
                        //this dex file doesn't contain the given class.
                        //continue searching
                    }
                } else {
                    Optional<? extends DexBackedClassDef> classDef =
                            dexBackedDexFile
                                    .getClasses()
                                    .stream()
                                    .filter(c -> fqcn.equals(SigUtils.signatureToName(c.getType())))
                                    .findFirst();
                    if (classDef.isPresent()) {
                        newMethod = classDef.get().getType() + "->" + method;
                    }
                    try {
                        emitter.onNext(disassembler.disassembleMethod(fqcn, newMethod));
                        dexFound = true;
                    } catch (IllegalStateException e) {
                        //this dex file doesn't contain the given method.
                        //continue searching
                    }
                }
            }
            if (!dexFound) {
                if (newMethod == null) {
                    throw new IllegalArgumentException(
                            String.format("The given class (%s) not found", fqcn));
                } else {
                    throw new IllegalArgumentException(
                            String.format(
                                    "The given class (%s) or method (%s) not found", fqcn, newMethod));
                }
            }
        });
    }

    /**
     * get dex file method references count of the specified dex file paths
     *
     * @param dexFilePaths e.g. ["classes.dex"]
     * @return Observable
     */
    public Observable<Integer> dexReferences(@Nullable List<String> dexFilePaths) {
        return Observable.create(emitter -> {
            Collection<Path> dexPaths;
            if (dexFilePaths == null || dexFilePaths.isEmpty()) {
                dexPaths = getDexFilesFrom(archive.getContentRoot());
            } else {
                dexPaths =
                        dexFilePaths
                                .stream()
                                .map(dexFile -> archive.getContentRoot().resolve(dexFile))
                                .collect(Collectors.toList());
            }
            for (Path dexPath : dexPaths) {
                DexFileStats stats =
                        DexFileStats.create(Collections.singleton(DexFiles.getDexFile(dexPath)));
                emitter.onNext(stats.referencedMethodCount);
                emitter.onComplete();
            }
        });
    }

    /**
     * get dex file list
     *
     * @return Observable
     */
    public Observable<String> dexList() {
        return Observable.create(emitter -> {
            getDexFilesFrom(archive.getContentRoot()).stream()
                    .map(path -> path.getFileName().toString())
                    .forEachOrdered(emitter::onNext);
            emitter.onComplete();

        });
    }

    @NonNull
    private ManifestData getManifestData(@NonNull Archive archive)
            throws IOException, ParserConfigurationException, SAXException {
        Path manifestPath = archive.getContentRoot().resolve(SdkConstants.ANDROID_MANIFEST_XML);
        byte[] manifestBytes =
                BinaryXmlParser.decodeXml(
                        SdkConstants.ANDROID_MANIFEST_XML, Files.readAllBytes(manifestPath));
        return AndroidManifestParser.parse(new ByteArrayInputStream(manifestBytes));
    }

    /**
     * get manifest debuggable
     *
     * @return boolean
     */
    public boolean manifestDebuggable() {
        try {
            ManifestData manifestData = getManifestData(archive);
            return manifestData.getDebuggable() != null ? manifestData.getDebuggable() : false;
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * get manifest permissions
     *
     * @return Observable
     */
    public Observable<String> manifestPermissions() {
        return Observable.create(emitter -> {
            List<String> output;
            try {
                output = aaptInvoker.dumpBadging(apkPath.toFile());
            } catch (ProcessException e) {
                throw new RuntimeException(e);
            }
            AndroidApplicationInfo apkInfo = AndroidApplicationInfo.parseBadging(output);
            for (String name : apkInfo.getPermissions()) {
                emitter.onNext(name);
            }
            emitter.onComplete();
        });
    }

    /**
     * get manifest targetSdk
     *
     * @return String
     */
    public String manifestTargetSdk() {
        try {
            ManifestData manifestData = getManifestData(archive);
            return String.valueOf(manifestData.getTargetSdkVersion());
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * get manifest minSdk
     *
     * @return String
     */
    public String manifestMinSdk() {
        try {
            ManifestData manifestData = getManifestData(archive);
            return
                    manifestData.getMinSdkVersion() != ManifestData.MIN_SDK_CODENAME
                            ? String.valueOf(manifestData.getMinSdkVersion())
                            : manifestData.getMinSdkVersionString();
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * get manifest version code
     *
     * @return String
     */
    public String manifestVersionCode() {
        try {
            ManifestData manifestData = getManifestData(archive);
            return String.format("%d", manifestData.getVersionCode());
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * get manifest version name
     *
     * @return String
     */
    public String manifestVersionName() {
        List<String> xml;
        try {
            xml = aaptInvoker.dumpBadging(apkPath.toFile());
        } catch (ProcessException e) {
            throw new RuntimeException(e);
        }
        AndroidApplicationInfo apkInfo = AndroidApplicationInfo.parseBadging(xml);
        return apkInfo.versionName;
    }

    /**
     * get manifest app id
     *
     * @return String
     */
    public String manifestAppId() {
        try {
            ManifestData manifestData = getManifestData(archive);
            return manifestData.getPackage();
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * get AndroidManifest.xml content
     *
     * @return String
     */
    public String manifestPrint() {
        try {
            Path path = archive.getContentRoot().resolve(SdkConstants.ANDROID_MANIFEST_XML);
            byte[] bytes = Files.readAllBytes(path);
            return new String(BinaryXmlParser.decodeXml(path.getFileName().toString(), bytes));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * get apk download size
     *
     * @return String
     * @see #setHumanReadableFlag(boolean)
     */
    public String apkDownloadSize() {
        ApkSizeCalculator sizeCalculator = ApkSizeCalculator.getDefault();
        return getSize(sizeCalculator.getFullApkDownloadSize(apkPath));
    }

    /**
     * get apk raw size
     *
     * @return String
     * @see #setHumanReadableFlag(boolean)
     */
    public String apkRawSize() {
        ApkSizeCalculator sizeCalculator = ApkSizeCalculator.getDefault();
        return getSize(sizeCalculator.getFullApkRawSize(apkPath));
    }

    /**
     * compare two apk and return the entry diff on size
     *
     * @param newApkFile        the new apk
     * @param patchSize         should compute size diff
     * @param showFilesOnly     only show files entry
     * @param showDifferentOnly only show different entry
     * @return Observable ApkDiffEntry
     */
    public Observable<ApkDiffEntry> apkCompare(
            @NonNull Path newApkFile,
            boolean patchSize,
            boolean showFilesOnly,
            boolean showDifferentOnly) {
        return Observable.create(emitter -> {
            try (Archive newApk = Archives.open(newApkFile)) {
                DefaultMutableTreeNode node;
                if (patchSize) {
                    node = ApkFileByFileDiffParser.createTreeNode(archive, newApk);
                } else {
                    node = ApkDiffParser.createTreeNode(archive, newApk);
                }
                dumpCompare(emitter, node, "", !showFilesOnly, showDifferentOnly);
                emitter.onComplete();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        });
    }

    private void dumpCompare(
            ObservableEmitter<ApkDiffEntry> emitter,
            @NonNull DefaultMutableTreeNode node,
            @NonNull String path,
            boolean showDirs,
            boolean diffOnly) {
        Object entry = node.getUserObject();
        if (entry instanceof ApkDiffEntry) {
            ApkDiffEntry diffEntry = (ApkDiffEntry) entry;
            if (node.getParent() == null) {
                path = "/";
            } else if (!path.endsWith("/")) {
                path = path + "/" + diffEntry.getName();
            } else {
                path = path + diffEntry.getName();
            }
            if (showDirs || !path.endsWith("/")) {
                if (!diffOnly || (diffEntry.getOldSize() != diffEntry.getNewSize())) {
                    emitter.onNext(diffEntry);
                }
            }
        }

        for (int i = 0; i < node.getChildCount(); i++) {
            dumpCompare(emitter, (DefaultMutableTreeNode) node.getChildAt(i), path, showDirs, diffOnly);
        }
    }

    /**
     * get apk summary info : packageId/versionCode/versionName/usesFeature/permissions
     *
     * @return AndroidApplicationInfo
     */
    public AndroidApplicationInfo apkSummary() {
        List<String> output;
        try {
            output = aaptInvoker.dumpBadging(apkPath.toFile());
        } catch (ProcessException e) {
            throw new RuntimeException(e);
        }
        AndroidApplicationInfo apkInfo = AndroidApplicationInfo.parseBadging(output);
        return apkInfo;
    }

    /**
     * get apk file entries path/size info list
     *
     * @return Observable
     */
    public Observable<ArchiveEntry> filesList(
            boolean showRawSize,
            boolean showDownloadSize) {

        return Observable.create(emitter -> {

            ArchiveNode node = ArchiveTreeStructure.create(archive);
            if (showRawSize) {
                ArchiveTreeStructure.updateRawFileSizes(node, ApkSizeCalculator.getDefault());
            }
            if (showDownloadSize) {
                ArchiveTreeStructure.updateDownloadFileSizes(node, ApkSizeCalculator.getDefault());
            }
            ArchiveTreeStream.preOrderStream(node)
                    .map(ArchiveNode::getData)
                    .forEachOrdered(emitter::onNext);
            emitter.onComplete();
        });
    }

    private String getSize(long bytes) {
        return humanReadableFlag ? getHumanizedSize(bytes) : String.valueOf(bytes);
    }

    /**
     * set size humanReadable
     *
     * @param humanReadableFlag
     */
    public void setHumanReadableFlag(boolean humanReadableFlag) {
        this.humanReadableFlag = humanReadableFlag;
    }
}
