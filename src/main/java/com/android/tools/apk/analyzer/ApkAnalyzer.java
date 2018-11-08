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
import com.android.tools.apk.analyzer.dex.*;
import com.android.tools.apk.analyzer.dex.tree.*;
import com.android.tools.apk.analyzer.internal.*;
import com.android.tools.proguard.ProguardMap;
import com.android.tools.proguard.ProguardSeedsMap;
import com.android.tools.proguard.ProguardUsagesMap;
import com.android.utils.NullLogger;
import com.google.common.base.Charsets;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Maps;
import com.google.devrel.gmscore.tools.apk.arsc.*;
import io.reactivex.Emitter;
import io.reactivex.Observable;
import io.reactivex.ObservableEmitter;
import io.reactivex.ObservableOnSubscribe;
import org.jf.dexlib2.dexbacked.DexBackedClassDef;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.xml.sax.SAXException;

import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeModel;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DecimalFormat;
import java.text.ParseException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Tool for getting all kinds of information about an APK, including: - basic package info, sizes
 * and files list - dex code - resources
 */
public class ApkAnalyzer {

    private static final String TOOLSDIR = "com.android.sdklib.toolsdir";

    @NonNull
    private final AaptInvoker aaptInvoker;
    private boolean humanReadableFlag;

    /**
     * Constructs a new command-line processor.
     */
    public ApkAnalyzer(@Nullable String osSdkFolder) {
        this.aaptInvoker = getAaptInvokerFromSdk(osSdkFolder);
    }

    public static AaptInvoker getAaptInvokerFromSdk(@Nullable String osSdkFolder) {
        if (osSdkFolder == null) {
            // We get passed a property for the tools dir
            String toolsDirProp = System.getProperty(TOOLSDIR);
            if (toolsDirProp == null) {
                // for debugging, it's easier to override using the process environment
                toolsDirProp = System.getenv(TOOLSDIR);
            }

            if (toolsDirProp != null) {
                // got back a level for the SDK folder
                File tools;
                if (!toolsDirProp.isEmpty()) {
                    try {
                        tools = new File(toolsDirProp).getCanonicalFile();
                        osSdkFolder = tools.getParent();
                    } catch (IOException e) {
                        // try using "." below
                    }
                }
                if (osSdkFolder == null) {
                    try {
                        tools = new File(".").getCanonicalFile();
                        osSdkFolder = tools.getParent();
                    } catch (IOException e) {
                        // Will print an error below since mSdkFolder is not defined
                    }
                }
            }
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

    public Observable<String> resPackages(@NonNull Path apk) {
        return Observable.create(emitter -> {
            try (Archive archive = Archives.open(apk)) {
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
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });


    }

    public Observable<byte[]> resXml(@NonNull Path apk, @NonNull String filePath) {
        return Observable.create(emitter -> {
            try (Archive archive = Archives.open(apk)) {
                Path path = archive.getContentRoot().resolve(filePath);
                byte[] bytes = Files.readAllBytes(path);
                if (!archive.isBinaryXml(path, bytes)) {
                    throw new IOException("The supplied file is not a binary XML resource.");
                }
                emitter.onNext(BinaryXmlParser.decodeXml(path.getFileName().toString(), bytes));
                emitter.onComplete();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    public Observable<String> resNames(
            @NonNull Path apk,
            @NonNull String type,
            @NonNull String config,
            @Nullable String packageName) {

        return Observable.create(emitter -> {
            try (Archive archive = Archives.open(apk)) {
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
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }

            throw new IllegalArgumentException(
                    String.format("Can't find specified resource configuration (%s)", config));
        });


    }

    public Observable<String> resValue(
            @NonNull Path apk,
            @NonNull String type,
            @NonNull String config,
            @NonNull String name,
            @Nullable String packageName) {

        return Observable.create(emitter -> {
            try (Archive archive = Archives.open(apk)) {
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
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
            throw new IllegalArgumentException(
                    String.format("Can't find specified resource configuration (%s)", config));
        });
    }

    public Observable<String> resConfigs(@NonNull Path apk, @NonNull String type, @Nullable String packageName) {
        return Observable.create(emitter -> {
            try (Archive archive = Archives.open(apk)) {
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
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });


    }

    public Observable<String> dexCode(@NonNull Path apk, @NonNull String fqcn, @Nullable final String method) {
        return Observable.create(emitter -> {
            String newMethod = method;
            try (Archive archive = Archives.open(apk)) {
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
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });
    }

    public Observable<String> dexPackages(
            @NonNull Path apk,
            @Nullable Path proguardFolderPath,
            @Nullable Path proguardMapFilePath,
            @Nullable Path proguardSeedsFilePath,
            @Nullable Path proguardUsagesFilePath,
            boolean showDefinedOnly,
            boolean showRemoved,
            @Nullable List<String> dexFilePaths) {

        return Observable.create(emitter -> {
            ProguardMappingFiles pfm;
            if (proguardFolderPath != null) {
                try {
                    pfm = ProguardMappingFiles.from(new Path[]{proguardFolderPath});
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            } else {
                pfm =
                        new ProguardMappingFiles(
                                proguardMapFilePath != null ? proguardMapFilePath : null,
                                proguardSeedsFilePath != null ? proguardSeedsFilePath : null,
                                proguardUsagesFilePath != null ? proguardUsagesFilePath : null);
            }

            List<String> loaded = new ArrayList<>(3);
            List<String> errors = new ArrayList<>(3);

            ProguardMap proguardMap = null;
            if (pfm.mappingFile != null) {
                proguardMap = new ProguardMap();
                try {
                    proguardMap.readFromReader(
                            new InputStreamReader(
                                    Files.newInputStream(pfm.mappingFile), Charsets.UTF_8));
                    loaded.add(pfm.mappingFile.getFileName().toString());
                } catch (IOException | ParseException e) {
                    errors.add(pfm.mappingFile.getFileName().toString());
                    proguardMap = null;
                }
            }
            ProguardSeedsMap seeds = null;
            if (pfm.seedsFile != null) {
                try {
                    seeds =
                            ProguardSeedsMap.parse(
                                    new InputStreamReader(
                                            Files.newInputStream(pfm.seedsFile), Charsets.UTF_8));
                    loaded.add(pfm.seedsFile.getFileName().toString());
                } catch (IOException e) {
                    errors.add(pfm.seedsFile.getFileName().toString());
                }
            }
            ProguardUsagesMap usage = null;
            if (pfm.usageFile != null) {
                try {
                    usage =
                            ProguardUsagesMap.parse(
                                    new InputStreamReader(
                                            Files.newInputStream(pfm.usageFile), Charsets.UTF_8));
                    loaded.add(pfm.usageFile.getFileName().toString());
                } catch (IOException e) {
                    errors.add(pfm.usageFile.getFileName().toString());
                }
            }

            if (!errors.isEmpty() && loaded.isEmpty()) {
                System.err.println(
                        "No Proguard mapping files found. The filenames must match one of: mapping.txt, seeds.txt, usage.txt");
            } else if (errors.isEmpty() && !loaded.isEmpty()) {
                System.err.println(
                        "Successfully loaded maps from: "
                                + loaded.stream().collect(Collectors.joining(", ")));
            } else if (!errors.isEmpty() && !loaded.isEmpty()) {
                System.err.println(
                        "Successfully loaded maps from: "
                                + loaded.stream().collect(Collectors.joining(", "))
                                + "\n"
                                + "There were problems loading: "
                                + errors.stream().collect(Collectors.joining(", ")));
            }

            ProguardMappings proguardMappings = new ProguardMappings(proguardMap, seeds, usage);
            boolean deobfuscateNames = proguardMap != null;

            try (Archive archive = Archives.open(apk)) {
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
                Map<Path, DexBackedDexFile> dexFiles = Maps.newHashMapWithExpectedSize(dexPaths.size());
                for (Path dexPath : dexPaths) {
                    dexFiles.put(dexPath, DexFiles.getDexFile(dexPath));
                }

                PackageTreeCreator treeCreator =
                        new PackageTreeCreator(proguardMappings, deobfuscateNames);
                DexPackageNode rootNode = treeCreator.constructPackageTree(dexFiles);

                DexViewFilters filters = new DexViewFilters();
                filters.setShowFields(true);
                filters.setShowMethods(true);
                filters.setShowReferencedNodes(!showDefinedOnly);
                filters.setShowRemovedNodes(showRemoved);

                FilteredTreeModel<DexElementNode> model = new FilteredTreeModel<>(rootNode, filters);
                dumpTree(emitter, model, rootNode, proguardMappings.seeds, proguardMappings.map);
                emitter.onComplete();
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });


    }

    private void dumpTree(Emitter<String> emitter,
                          @NonNull TreeModel model,
                          @NonNull DexElementNode node,
                          ProguardSeedsMap seeds,
                          ProguardMap map) {
        StringBuilder sb = new StringBuilder();

        if (node instanceof DexClassNode) {
            sb.append("C ");
        } else if (node instanceof DexPackageNode) {
            sb.append("P ");
        } else if (node instanceof DexMethodNode) {
            sb.append("M ");
        } else if (node instanceof DexFieldNode) {
            sb.append("F ");
        }

        if (node.isRemoved()) {
            sb.append("x ");
        } else if (node.isSeed(seeds, map, true)) {
            sb.append("k ");
        } else if (!node.isDefined()) {
            sb.append("r ");
        } else {
            sb.append("d ");
        }

        sb.append(node.getMethodDefinitionsCount());
        sb.append('\t');
        sb.append(node.getMethodReferencesCount());
        sb.append('\t');
        sb.append(getSize(node.getSize()));
        sb.append('\t');

        if (node instanceof DexPackageNode) {
            if (node.getParent() == null) {
                sb.append("<TOTAL>");
            } else {
                sb.append(((DexPackageNode) node).getPackageName());
            }
        } else if (node instanceof DexClassNode) {
            DexPackageNode parent = (DexPackageNode) node.getParent();
            if (parent != null && parent.getPackageName() != null) {
                sb.append(parent.getPackageName());
                sb.append(".");
            }
            sb.append(node.getName());
        } else if (node instanceof DexMethodNode | node instanceof DexFieldNode) {
            DexPackageNode parent = (DexPackageNode) node.getParent().getParent();
            if (parent != null && parent.getPackageName() != null) {
                sb.append(parent.getPackageName());
                sb.append(".");
            }
            sb.append(node.getParent().getName());
            sb.append(" ");
            sb.append(node.getName());
        }

        emitter.onNext(sb.toString());

        for (int i = 0; i < model.getChildCount(node); i++) {
            dumpTree(emitter, model, (DexElementNode) model.getChild(node, i), seeds, map);
        }
    }

    public Observable<String> dexReferences(@NonNull Path apk, @Nullable List<String> dexFilePaths) {
        return Observable.create(emitter -> {
            try (Archive archive = Archives.open(apk)) {
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
                    emitter.onNext(String.format("%s\t%d", dexPath.getFileName().toString(), stats.referencedMethodCount));
                    emitter.onComplete();
                }
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        });


    }

    public Observable<String> dexList(@NonNull Path apk) {
        return Observable.create(new ObservableOnSubscribe<String>() {
            @Override
            public void subscribe(ObservableEmitter<String> emitter) throws Exception {
                try (Archive archive = Archives.open(apk)) {
                    getDexFilesFrom(archive.getContentRoot()).stream()
                            .map(path -> path.getFileName().toString())
                            .forEachOrdered(emitter::onNext);
                    emitter.onComplete();
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
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

    public boolean manifestDebuggable(@NonNull Path apk) {
        try (Archive archive = Archives.open(apk)) {
            ManifestData manifestData = getManifestData(archive);
            boolean debuggable =
                    manifestData.getDebuggable() != null ? manifestData.getDebuggable() : false;
            return debuggable;
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public Observable<String> manifestPermissions(@NonNull Path apk) {
        return Observable.create(new ObservableOnSubscribe<String>() {
            @Override
            public void subscribe(ObservableEmitter<String> emitter) throws Exception {
                List<String> output;
                try {
                    output = aaptInvoker.dumpBadging(apk.toFile());
                } catch (ProcessException e) {
                    throw new RuntimeException(e);
                }
                AndroidApplicationInfo apkInfo = AndroidApplicationInfo.parseBadging(output);
                for (String name : apkInfo.getPermissions()) {
                    emitter.onNext(name);
                }
                emitter.onComplete();
            }
        });

    }

    public String manifestTargetSdk(@NonNull Path apk) {
        try (Archive archive = Archives.open(apk)) {
            ManifestData manifestData = getManifestData(archive);
            return String.valueOf(manifestData.getTargetSdkVersion());
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String manifestMinSdk(@NonNull Path apk) {
        try (Archive archive = Archives.open(apk)) {
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

    public String manifestVersionCode(@NonNull Path apk) {
        try (Archive archive = Archives.open(apk)) {
            ManifestData manifestData = getManifestData(archive);
            return String.format("%d", manifestData.getVersionCode());
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String manifestVersionName(@NonNull Path apk) {
        List<String> xml;
        try {
            xml = aaptInvoker.dumpBadging(apk.toFile());
        } catch (ProcessException e) {
            throw new RuntimeException(e);
        }
        AndroidApplicationInfo apkInfo = AndroidApplicationInfo.parseBadging(xml);
        return apkInfo.versionName;
    }

    public String manifestAppId(@NonNull Path apk) {
        try (Archive archive = Archives.open(apk)) {
            ManifestData manifestData = getManifestData(archive);
            return manifestData.getPackage();
        } catch (SAXException | ParserConfigurationException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String manifestPrint(@NonNull Path apk) {
        try (Archive archive = Archives.open(apk)) {
            Path path = archive.getContentRoot().resolve(SdkConstants.ANDROID_MANIFEST_XML);
            byte[] bytes = Files.readAllBytes(path);
            return new String(BinaryXmlParser.decodeXml(path.getFileName().toString(), bytes));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    public String apkDownloadSize(@NonNull Path apk) {
        ApkSizeCalculator sizeCalculator = ApkSizeCalculator.getDefault();
        return getSize(sizeCalculator.getFullApkDownloadSize(apk));
    }

    public String apkRawSize(@NonNull Path apk) {
        ApkSizeCalculator sizeCalculator = ApkSizeCalculator.getDefault();
        return getSize(sizeCalculator.getFullApkRawSize(apk));
    }

    public Observable<ApkDiffEntry> apkCompare(
            @NonNull Path oldApkFile,
            @NonNull Path newApkFile,
            boolean patchSize,
            boolean showFilesOnly,
            boolean showDifferentOnly) {
        return Observable.create(new ObservableOnSubscribe<ApkDiffEntry>() {
            @Override
            public void subscribe(ObservableEmitter<ApkDiffEntry> emitter) throws Exception {
                try (Archive oldApk = Archives.open(oldApkFile);
                     Archive newApk = Archives.open(newApkFile)) {
                    DefaultMutableTreeNode node;
                    if (patchSize) {
                        node = ApkFileByFileDiffParser.createTreeNode(oldApk, newApk);
                    } else {
                        node = ApkDiffParser.createTreeNode(oldApk, newApk);
                    }
                    dumpCompare(emitter, node, "", !showFilesOnly, showDifferentOnly);
                    emitter.onComplete();
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
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


    public AndroidApplicationInfo apkSummary(@NonNull Path apk) {
        List<String> output;
        try {
            output = aaptInvoker.dumpBadging(apk.toFile());
        } catch (ProcessException e) {
            throw new RuntimeException(e);
        }
        AndroidApplicationInfo apkInfo = AndroidApplicationInfo.parseBadging(output);
        return apkInfo;
    }

    public Observable<String> filesList(
            @NonNull Path apk,
            boolean showRawSize,
            boolean showDownloadSize,
            boolean showFilesOnly) {

        return Observable.create(new ObservableOnSubscribe<String>() {

            @Override
            public void subscribe(ObservableEmitter<String> emitter) throws Exception {
                try (Archive archive = Archives.open(apk)) {
                    ArchiveNode node = ArchiveTreeStructure.create(archive);
                    if (showRawSize) {
                        ArchiveTreeStructure.updateRawFileSizes(node, ApkSizeCalculator.getDefault());
                    }
                    if (showDownloadSize) {
                        ArchiveTreeStructure.updateDownloadFileSizes(node, ApkSizeCalculator.getDefault());
                    }
                    ArchiveTreeStream.preOrderStream(node)
                            .map(
                                    n -> {
                                        String path = n.getData().getFullPathString();
                                        long rawSize = n.getData().getRawFileSize();
                                        long downloadSize = n.getData().getDownloadFileSize();

                                        if (showDownloadSize) {
                                            path = getSize(downloadSize) + "\t" + path;
                                        }
                                        if (showRawSize) {
                                            path = getSize(rawSize) + "\t" + path;
                                        }
                                        return path;
                                    })
                            .filter(path -> !showFilesOnly || !path.endsWith("/"))
                            .forEachOrdered(emitter::onNext);
                    emitter.onComplete();
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
        });


    }

    private String getSize(long bytes) {
        return humanReadableFlag ? getHumanizedSize(bytes) : String.valueOf(bytes);
    }

    public void setHumanReadableFlag(boolean humanReadableFlag) {
        this.humanReadableFlag = humanReadableFlag;
    }
}
