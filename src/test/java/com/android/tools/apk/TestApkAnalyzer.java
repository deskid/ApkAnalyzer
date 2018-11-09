package com.android.tools.apk;

import com.android.tools.apk.analyzer.ApkAnalyzer;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class TestApkAnalyzer {

    private ApkAnalyzer apkAnalyzer;
    private Path path = new File("assets/demo.apk").toPath();
    private Path path2 = new File("assets/demo2.apk").toPath();

    @Before
    public void setup() throws IOException {
        apkAnalyzer = new ApkAnalyzer(path);
        apkAnalyzer.setHumanReadableFlag(true);
    }

    @After
    public void close() throws IOException {
        apkAnalyzer.close();
    }

    @Test
    public void testResConfigs() {
        apkAnalyzer.resConfigs("string", null)
                .take(1)
                .subscribe(s -> Assert.assertEquals(s, "default"));
    }


    @Test
    public void testResNames() {
        apkAnalyzer.resNames("string", "default", null)
                .take(1)
                .subscribe(s -> Assert.assertEquals(s, "abc_action_bar_home_description"));
    }

    @Test
    public void testResValue() {
        apkAnalyzer.resValue("string", "default", "abc_action_bar_home_description", null)
                .subscribe(s -> Assert.assertEquals(s, "Navigate home"));
    }

    @Test
    public void testResId() {
        apkAnalyzer.resId("string", "default", "abc_action_bar_home_description", null)
                .subscribe(s -> Assert.assertEquals(s, "0x7f0d0000"));
    }

    @Test
    public void testResPackages() {
        apkAnalyzer.resPackages()
                .subscribe(s -> Assert.assertEquals(s, "com.github.deskid.focusreader"));
    }


    @Test
    public void testResXml() throws IOException {
        Assert.assertEquals(apkAnalyzer.resXml("res/layout/abc_search_view.xml").indexOf("<?xml version=\"1.0\" encoding=\"utf-8\"?>"), 0);
    }

    @Test
    public void testDexCode() {
        apkAnalyzer.dexCode("com.github.deskid.focusreader.activity.BaseActivity", "onStart()V")
                .subscribe(s -> Assert.assertEquals(s.indexOf(".method protected onStart()V"), 0));
    }

    @Test
    public void testDexList() {
        apkAnalyzer.dexList()
                .subscribe(s -> Assert.assertEquals("classes.dex", s));
    }

    @Test
    public void testDexReferences() {
        List<String> dexFileList = new ArrayList<>();
        dexFileList.add("classes.dex");
        apkAnalyzer.dexReferences(dexFileList)
                .subscribe(s -> Assert.assertEquals("54951", s.toString()));
    }


    @Test
    public void testGetManifestData() {
        Assert.assertEquals(apkAnalyzer.manifestDebuggable(), true);
    }


    @Test
    public void testManifestPermissions() {
        apkAnalyzer.manifestPermissions()
                .take(1)
                .subscribe(s -> Assert.assertEquals("android.permission.INTERNET", s));
    }


    @Test
    public void testManifestTargetSdk() {
        Assert.assertEquals(apkAnalyzer.manifestTargetSdk(), "27");
    }

    @Test
    public void testManifestMinSdk() {
        Assert.assertEquals(apkAnalyzer.manifestMinSdk(), "21");
    }


    @Test
    public void testManifestVersionCode() {
        Assert.assertEquals(apkAnalyzer.manifestVersionCode(), "1");
    }

    @Test
    public void testManifestVersionName() {
        Assert.assertEquals(apkAnalyzer.manifestVersionName(), "?");
    }

    @Test
    public void testManifestAppId() {
        Assert.assertEquals(apkAnalyzer.manifestAppId(), "com.github.deskid.focusreader");
    }

    @Test
    public void testManifestPrint() {
        Assert.assertEquals(apkAnalyzer.manifestPrint().indexOf("<?xml version=\"1.0\" encoding=\"utf-8\"?>"), 0);
    }

    @Test
    public void testApkDownloadSize() {
        Assert.assertEquals(apkAnalyzer.apkDownloadSize(), "3.7MB");
    }

    @Test
    public void testApkRawSize() {
        Assert.assertEquals(apkAnalyzer.apkRawSize(), "4.1MB");
    }

    @Test
    public void testApkCompare() {
        apkAnalyzer.apkCompare(path2, true, false, false)
                .take(1)
                .subscribe(apkDiffEntry -> {
                    Assert.assertEquals(apkDiffEntry.getName(), "demo.apk");
                });
    }

    @Test
    public void testApkSummary() {
        Assert.assertEquals(apkAnalyzer.apkSummary().getPermissions().toString(), "[android.permission.INTERNET, android.permission.ACCESS_NETWORK_STATE]");
    }

    @Test
    public void testFilesList() {
        apkAnalyzer.filesList(true, true)
                .takeLast(1)
                .subscribe(archiveEntry -> {
                    Assert.assertEquals(archiveEntry.getFullPathString(), "/AndroidManifest.xml");
                });
    }

}
