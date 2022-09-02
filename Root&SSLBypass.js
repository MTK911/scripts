Java.perform(function() {
function replaceFinaleField(object, fieldName, value){    
    var field =  object.class.getDeclaredField(fieldName)
    var result = field.get(object.class);
    var obj = {"plugin": "bypass", "property" : "Build Properties", "real_value" : fieldName.toString() + " = " + result.toString(), "return_value" : fieldName.toString() + " = " + value.toString()};
    send(JSON.stringify(obj));
    field.setAccessible(true);
    field.set(null, value);
}

function bypass_build_properties(){
        // Class containing const that we want to modify
        const Build = Java.use("android.os.Build")

        // reflection class for changing const
        const Field = Java.use('java.lang.reflect.Field')
        const Class = Java.use('java.lang.Class')

        // Replacing Build static fields
        replaceFinaleField(Build, "FINGERPRINT", "abcd/C1505:4.1.1/11.3.A.2.13:user/release-keys")
        replaceFinaleField(Build, "MODEL", "C1505")
        replaceFinaleField(Build, "MANUFACTURER", "Sony")
        replaceFinaleField(Build, "BRAND", "Xperia")
        replaceFinaleField(Build, "BOARD", "7x27")
        replaceFinaleField(Build, "ID", "11.3.A.2.13")
        replaceFinaleField(Build, "SERIAL", "abcdef123")
        replaceFinaleField(Build, "TAGS", "release-keys")
        replaceFinaleField(Build, "USER", "administrator")
}

function bypass_phonenumber(){
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')
    TelephonyManager.getLine1Number.overload().implementation = function(){
        var result = this.getLine1Number();
        var return_value = "060102030405";
        var obj = {"plugin": "bypass", "property" : "Phone number", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    }
}

function bypass_deviceid(){
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')
    TelephonyManager.getDeviceId.overload().implementation = function(){
        var result = this.getDeviceId();
        var return_value = "012343545456445";
        var obj = {"plugin": "bypass", "property" : "Device id", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value
    }
}

function bypass_imsi(){
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')
    TelephonyManager.getSubscriberId.overload().implementation = function(){
        var result = this.getSubscriberId();
        var return_value = "310260000000111";
        var obj = {"plugin": "bypass", "property" : "Suscriber ID", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    }
}

function bypass_operator_name(){
    const TelephonyManager = Java.use('android.telephony.TelephonyManager')
    TelephonyManager.getNetworkOperatorName.overload().implementation = function(){
        var result = this.getNetworkOperatorName();
        var return_value = "not";
        var obj = {"plugin": "bypass", "property" : "Network Operator Name", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    }
}

function bypass_sim_operator_name(){
    const TelephonyManager = Java.use('android.telephony.TelephonyManager');

    var telephonyManagerMethods = ['getSimOperatorName', 'getSimOperator'];
    var return_value = "not";

    telephonyManagerMethods.forEach(function(method, i) {
        TelephonyManager[method].overload().implementation = function() {
            var result = this[method]();
            var obj = {"plugin": "bypass", "property" : "Sim Operator", "real_value" : result.toString(), "return_value" : return_value};
            send(JSON.stringify(obj));
            return return_value;
        }
    });
}

function bypass_country_iso(){
    const TelephonyManager = Java.use('android.telephony.TelephonyManager');

    TelephonyManager.getNetworkCountryIso.overload('int').implementation = function(slotIndex){
        var result = this.getNetworkCountryIso(slotIndex);
        var return_value = "not";
        var obj = {"plugin": "bypass", "property" : "Network Country Iso", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    };

    TelephonyManager.getNetworkCountryIso.overload().implementation = function(){
        var result = this.getNetworkCountryIso();
        var return_value = "not";
        var obj = {"plugin": "bypass", "property" : "Network Country Iso", "real_value" : result.toString(), "return_value" : return_value};
        send(JSON.stringify(obj));
        return return_value;
    }
}

function bypass_has_file(){
    const File = Java.use("java.io.File")
    const KnownFiles= [
        "ueventd.android_x86.rc",
        "x86.prop",
        "ueventd.ttVM_x86.rc",
        "init.ttVM_x86.rc",
        "fstab.ttVM_x86",
        "fstab.vbox86",
        "init.vbox86.rc",
        "ueventd.vbox86.rc",
        "/dev/socket/qemud",
        "/dev/qemu_pipe",
        "/system/lib/libc_malloc_debug_qemu.so",
        "/sys/qemu_trace",
        "/system/bin/qemu-props",
        "/dev/socket/genyd",
        "/dev/socket/baseband_genyd",
        "/proc/tty/drivers",
        "/proc/cpuinfo",
		"/sbin/magisk"
    ]

   
        File.exists.implementation = function () {
          var x = this.getAbsolutePath();
          var return_value = false;

          for(var i=0; i<KnownFiles.length; i++){
            
            if(KnownFiles[i] == x){
              var obj = {"plugin": "bypass", "property" : "Has File", "real_value" : x.toString(), "return_value" : return_value};
              send(JSON.stringify(obj));
              return return_value;
            }
          }
      
          return this.exists();
        };
}

function bypass_processbuilder(){
    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    ProcessBuilder.$init.overload('[Ljava.lang.String;').implementation = function(x){
        var result = this.$init(x);
        var return_value = undefined;
        var obj = {"plugin": "bypass", "property" : "ProcessBuilder", "real_value" : x + "\n" + result, "return_value" : x + "\n" + return_value};
        send(JSON.stringify(obj));
        return return_value;
    }
}


function bypass_system_properties() {
    /*
    * Function used to bypass common checks to
    * Android OS properties
    * Bypass the props checking from this git : https://github.com/strazzere/anti-emulator
    * Also used https://www.virusbulletin.com/virusbulletin/2019/01/vb2018-paper-unpacking-packed-unpacker-reversing-android-anti-analysis-native-library
    */
    const SystemProperties = Java.use('android.os.SystemProperties')
    const String = Java.use('java.lang.String')
    const Properties = {
        "init.svc.qemud": null,
        "init.svc.qemu-props": null,
        "qemu.hw.mainkeys": null,
        "qemu.sf.fake_camera": null,
        "qemu.sf.lcd_density": null,
        "ro.bootloader": "xxxxx",
        "ro.bootmode": "xxxxxx",
        "ro.hardware": "xxxxxx",
        "ro.kernel.android.qemud": null,
        "ro.kernel.qemu.gles": null,
        "ro.kernel.qemu": "xxxxxx",
        "ro.product.device": "xxxxx",
        "ro.product.model": "xxxxxx",
        "ro.product.name": "xxxxxx",
        "ro.serialno": null,
        "init.svc.gce_fs_monitor": "xxxxxx",
        "init.svc.dumpeventlog": "xxxxxx",
        "init.svc.dumpipclog": "xxxxxx",
        "init.svc.dumplogcat": "xxxxxx",
        "init.svc.dumplogcat-efs": "xxxxxx",
        "init.svc.filemon": "xxxxxx",
        "ro.hardware.virtual_device": "xxxxx",
        "ro.kernel.androidboot.hardware": "xxxxx",
        "ro.boot.hardware": "xxxxx",
        "ro.boot.selinux": "enable",
        "ro.factorytest": "xxxxxx",
        "ro.kernel.android.checkjni": "xxxxxx",
        "ro.build.product": "xxxxx",
        "ro.product.manufacturer": "xxxxx",
        "ro.product.brand": "xxxxx",
        "init.svc.vbox86-setup": null,
        "init.svc.goldfish-logcat": null,
        "init.svc.goldfish-setup": null,

    }

    SystemProperties.get.overload('java.lang.String').implementation = function(x){
        var result = this.get(x);
        if (x in Properties){
            var obj = {"plugin": "bypass", "property" : "System Property", "real_value" : x.toString() + " = " + result.toString(), "return_value" : x.toString() + " = " + Properties[x].toString()};
            send(JSON.stringify(obj));
            return Properties[x];
        }
        return this.get(x);
    }

}
    var RootPackages = ["com.noshufou.android.su", "com.noshufou.android.su.elite", "eu.chainfire.supersu",
        "com.koushikdutta.superuser", "com.thirdparty.superuser", "com.yellowes.su", "com.koushikdutta.rommanager",
        "com.koushikdutta.rommanager.license", "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
        "com.ramdroid.appquarantine", "com.ramdroid.appquarantinepro", "com.devadvance.rootcloak", "com.devadvance.rootcloakplus",
        "de.robv.android.xposed.installer", "com.saurik.substrate", "com.zachspong.temprootremovejb", "com.amphoras.hidemyroot",
        "com.amphoras.hidemyrootadfree", "com.formyhm.hiderootPremium", "com.formyhm.hideroot", "me.phh.superuser",
        "eu.chainfire.supersu.pro", "com.kingouser.com"
    ];

    var RootBinaries = ["su", "busybox", "supersu", "Superuser.apk", "KingoUser.apk", "SuperSu.apk", "magisk"];

    var RootProperties = {
        "ro.build.selinux": "1",
        "ro.debuggable": "0",
        "service.adb.root": "0",
        "ro.secure": "1"
    };

    var RootPropertiesKeys = [];

    for (var k in RootProperties) RootPropertiesKeys.push(k);

    var PackageManager = Java.use("android.app.ApplicationPackageManager");

    var Runtime = Java.use('java.lang.Runtime');

    var NativeFile = Java.use('java.io.File');

    var String = Java.use('java.lang.String');

    var SystemProperties = Java.use('android.os.SystemProperties');

    var BufferedReader = Java.use('java.io.BufferedReader');

    var ProcessBuilder = Java.use('java.lang.ProcessBuilder');

    var StringBuffer = Java.use('java.lang.StringBuffer');

    var loaded_classes = Java.enumerateLoadedClassesSync();

    send("Loaded " + loaded_classes.length + " classes!");

    var useKeyInfo = false;

    var useProcessManager = false;

    send("loaded: " + loaded_classes.indexOf('java.lang.ProcessManager'));

    if (loaded_classes.indexOf('java.lang.ProcessManager') != -1) {
        try {


        } catch (err) {
            send("ProcessManager Hook failed: " + err);
        }
    } else {
        send("ProcessManager hook not loaded");
    }

    var KeyInfo = null;

    if (loaded_classes.indexOf('android.security.keystore.KeyInfo') != -1) {
        try {


        } catch (err) {
            send("KeyInfo Hook failed: " + err);
        }
    } else {
        send("KeyInfo hook not loaded");
    }

    PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pname, flags) {
        var shouldFakePackage = (RootPackages.indexOf(pname) > -1);
        if (shouldFakePackage) {
            send("Bypass root check for package: " + pname);
            pname = "set.package.name.to.a.fake.one.so.we.can.bypass.it";
        }
        return this.getPackageInfo.call(this, pname, flags);
    };

    NativeFile.exists.implementation = function() {
        var name = NativeFile.getName.call(this);
        var shouldFakeReturn = (RootBinaries.indexOf(name) > -1);
        if (shouldFakeReturn) {
            send("Bypass return value for binary: " + name);
            return false;
        } else {
            return this.exists.call(this);
        }
    };

    var exec = Runtime.exec.overload('[Ljava.lang.String;');
    var exec1 = Runtime.exec.overload('java.lang.String');
    var exec2 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;');
    var exec3 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;');
    var exec4 = Runtime.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File');
    var exec5 = Runtime.exec.overload('java.lang.String', '[Ljava.lang.String;', 'java.io.File');

    exec5.implementation = function(cmd, env, dir) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec5.call(this, cmd, env, dir);
    };

    exec4.implementation = function(cmdarr, env, file) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec4.call(this, cmdarr, env, file);
    };

    exec3.implementation = function(cmdarr, envp) {
        for (var i = 0; i < cmdarr.length; i = i + 1) {
            var tmp_cmd = cmdarr[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmdarr + " command");
                return exec1.call(this, fakeCmd);
            }
        }
        return exec3.call(this, cmdarr, envp);
    };

    exec2.implementation = function(cmd, env) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec2.call(this, cmd, env);
    };

    exec.implementation = function(cmd) {
        for (var i = 0; i < cmd.length; i = i + 1) {
            var tmp_cmd = cmd[i];
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id" || tmp_cmd == "sh") {
                var fakeCmd = "grep";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }

            if (tmp_cmd == "su") {
                var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
                send("Bypass " + cmd + " command");
                return exec1.call(this, fakeCmd);
            }
        }

        return exec.call(this, cmd);
    };

    exec1.implementation = function(cmd) {
        if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id" || cmd == "sh") {
            var fakeCmd = "grep";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        if (cmd == "su") {
            var fakeCmd = "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled";
            send("Bypass " + cmd + " command");
            return exec1.call(this, fakeCmd);
        }
        return exec1.call(this, cmd);
    };

    String.contains.implementation = function(name) {
        if (name == "test-keys") {
            send("Bypass test-keys check");
            return false;
        }
        return this.contains.call(this, name);
    };

    var get = SystemProperties.get.overload('java.lang.String');

    get.implementation = function(name) {
        if (RootPropertiesKeys.indexOf(name) != -1) {
            send("Bypass " + name);
            return RootProperties[name];
        }
        return this.get.call(this, name);
    };

    Interceptor.attach(Module.findExportByName("libc.so", "fopen"), {
        onEnter: function(args) {
            var path = Memory.readCString(args[0]);
            path = path.split("/");
            var executable = path[path.length - 1];
            var shouldFakeReturn = (RootBinaries.indexOf(executable) > -1)
            if (shouldFakeReturn) {
                Memory.writeUtf8String(args[0], "/notexists");
                send("Bypass native fopen");
            }
        },
        onLeave: function(retval) {

        }
    });

    Interceptor.attach(Module.findExportByName("libc.so", "system"), {
        onEnter: function(args) {
            var cmd = Memory.readCString(args[0]);
            send("SYSTEM CMD: " + cmd);
            if (cmd.indexOf("getprop") != -1 || cmd == "mount" || cmd.indexOf("build.prop") != -1 || cmd == "id") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "grep");
            }
            if (cmd == "su") {
                send("Bypass native system: " + cmd);
                Memory.writeUtf8String(args[0], "justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled");
            }
        },
        onLeave: function(retval) {

        }
    });




    BufferedReader.readLine.overload().implementation = function() {
        var text = this.readLine.call(this);
        if (text === null) {

        } else {
            var shouldFakeRead = (text.indexOf("ro.build.tags=test-keys") > -1);
            if (shouldFakeRead) {
                send("Bypass build.prop file read");
                text = text.replace("ro.build.tags=test-keys", "ro.build.tags=release-keys");
            }
        }
        return text;
    };

    var executeCommand = ProcessBuilder.command.overload('java.util.List');

    ProcessBuilder.start.implementation = function() {
        var cmd = this.command.call(this);
        var shouldModifyCommand = false;
        for (var i = 0; i < cmd.size(); i = i + 1) {
            var tmp_cmd = cmd.get(i).toString();
            if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd.indexOf("mount") != -1 || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd.indexOf("id") != -1) {
                shouldModifyCommand = true;
            }
        }
        if (shouldModifyCommand) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["grep"]);
            return this.start.call(this);
        }
        if (cmd.indexOf("su") != -1) {
            send("Bypass ProcessBuilder " + cmd);
            this.command.call(this, ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"]);
            return this.start.call(this);
        }

        return this.start.call(this);
    };

    if (useProcessManager) {
        var ProcManExec = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.io.File', 'boolean');
        var ProcManExecVariant = ProcessManager.exec.overload('[Ljava.lang.String;', '[Ljava.lang.String;', 'java.lang.String', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'java.io.FileDescriptor', 'boolean');

        ProcManExec.implementation = function(cmd, env, workdir, redirectstderr) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExec.call(this, fake_cmd, env, workdir, redirectstderr);
        };

        ProcManExecVariant.implementation = function(cmd, env, directory, stdin, stdout, stderr, redirect) {
            var fake_cmd = cmd;
            for (var i = 0; i < cmd.length; i = i + 1) {
                var tmp_cmd = cmd[i];
                if (tmp_cmd.indexOf("getprop") != -1 || tmp_cmd == "mount" || tmp_cmd.indexOf("build.prop") != -1 || tmp_cmd == "id") {
                    var fake_cmd = ["grep"];
                    send("Bypass " + cmdarr + " command");
                }

                if (tmp_cmd == "su") {
                    var fake_cmd = ["justafakecommandthatcannotexistsusingthisshouldthowanexceptionwheneversuiscalled"];
                    send("Bypass " + cmdarr + " command");
                }
            }
            return ProcManExecVariant.call(this, fake_cmd, env, directory, stdin, stdout, stderr, redirect);
        };
    }

    if (useKeyInfo) {
        KeyInfo.isInsideSecureHardware.implementation = function() {
            send("Bypass isInsideSecureHardware");
            return true;
        }
    }

    var File = Java.use("java.io.File");
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var quiet_output = false;

    function quiet_send(data) {

        if (quiet_output) {

            return;
        }

        send(data)
    }



    var X509Certificate = Java.use("java.security.cert.X509Certificate");
    var TrustManager;
    try {
        TrustManager = Java.registerClass({
            name: 'org.wooyun.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {},
                getAcceptedIssuers: function() {


                    return [];
                }
            }
        });
    } catch (e) {
        quiet_send("registerClass from X509TrustManager >>>>>>>> " + e.message);
    }


    var TrustManagers = [TrustManager.$new()];

    try {

        var TLS_SSLContext = SSLContext.getInstance("TLS");
        TLS_SSLContext.init(null, TrustManagers, null);
        var EmptySSLFactory = TLS_SSLContext.getSocketFactory();
    } catch (e) {
        quiet_send(e.message);
    }

    send('Custom, Empty TrustManager ready');

    var SSLContext_init = SSLContext.init.overload(
        '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');

    SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {

        quiet_send('Overriding SSLContext.init() with the custom TrustManager');

        SSLContext_init.call(this, null, TrustManagers, null);
    };




    try {

        var CertificatePinner = Java.use('okhttp3.CertificatePinner');

        quiet_send('OkHTTP 3.x Found');

        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function() {

            quiet_send('OkHTTP 3.x check() called. Not throwing an exception.');
        }

    } catch (err) {



        if (err.message.indexOf('ClassNotFoundException') === 0) {

            throw new Error(err);
        }
    }


    try {

        var PinningTrustManager = Java.use('appcelerator.https.PinningTrustManager');

        send('Appcelerator Titanium Found');

        PinningTrustManager.checkServerTrusted.implementation = function() {

            quiet_send('Appcelerator checkServerTrusted() called. Not throwing an exception.');
        }

    } catch (err) {



        if (err.message.indexOf('ClassNotFoundException') === 0) {

            throw new Error(err);
        }
    }


    try {
        var OkHttpClient = Java.use("com.squareup.okhttp.OkHttpClient");
        OkHttpClient.setCertificatePinner.implementation = function(certificatePinner) {

            quiet_send("OkHttpClient.setCertificatePinner Called!");
            return this;
        };


        var CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
        CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function(p0, p1) {

            quiet_send("okhttp Called! [Certificate]");
            return;
        };
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(p0, p1) {

            quiet_send("okhttp Called! [List]");
            return;
        };
    } catch (e) {
        quiet_send("com.squareup.okhttp not found");
    }




    var WebViewClient = Java.use("android.webkit.WebViewClient");

    WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
        quiet_send("WebViewClient onReceivedSslError invoke");

        sslErrorHandler.proceed();
        return;
    };

    WebViewClient.onReceivedError.overload('android.webkit.WebView', 'int', 'java.lang.String', 'java.lang.String').implementation = function(a, b, c, d) {
        quiet_send("WebViewClient onReceivedError invoked");
        return;
    };

    WebViewClient.onReceivedError.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest', 'android.webkit.WebResourceError').implementation = function() {
        quiet_send("WebViewClient onReceivedError invoked");
        return;
    };


    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");


    HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
        quiet_send("HttpsURLConnection.setDefaultHostnameVerifier invoked");
        return null;
    };


    HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
        quiet_send("HttpsURLConnection.setSSLSocketFactory invoked");
        return null;
    };


    HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
        quiet_send("HttpsURLConnection.setHostnameVerifier invoked");
        return null;
    };


    var TrustHostnameVerifier;
    try {
        TrustHostnameVerifier = Java.registerClass({
            name: 'org.wooyun.TrustHostnameVerifier',
            implements: [HostnameVerifier],
            method: {
                verify: function(hostname, session) {
                    return true;
                }
            }
        });

    } catch (e) {

        quiet_send("registerClass from hostnameVerifier >>>>>>>> " + e.message);
    }

    try {
        var RequestParams = Java.use('org.xutils.http.RequestParams');
        RequestParams.setSslSocketFactory.implementation = function(sslSocketFactory) {
            sslSocketFactory = EmptySSLFactory;
            return null;
        }

        RequestParams.setHostnameVerifier.implementation = function(hostnameVerifier) {
            hostnameVerifier = TrustHostnameVerifier.$new();
            return null;
        }

    } catch (e) {
        quiet_send("Xutils hooks not Found");
    }


    try {
        var AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
        AbstractVerifier.verify.overload('java.lang.String', '[Ljava.lang.String', '[Ljava.lang.String', 'boolean').implementation = function() {
            quiet_send("httpclientandroidlib Hooks");
            return null;
        }
    } catch (e) {
        quiet_send("httpclientandroidlib Hooks not found");
    }


    var TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");

    try {

        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            quiet_send("TrustManagerImpl verifyChain called");



            return untrustedChain;
        }
    } catch (e) {
        quiet_send("TrustManagerImpl verifyChain nout found below 7.0");
    }

    try {
        var OpenSSLSocketImpl = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl');
        OpenSSLSocketImpl.verifyCertificateChain.implementation = function(certRefs, authMethod) {
            quiet_send('OpenSSLSocketImpl.verifyCertificateChain');
        }

        quiet_send('OpenSSLSocketImpl pinning')
    } catch (err) {
        quiet_send('OpenSSLSocketImpl pinner not found');
    }
    try {
        var Activity = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
        Activity.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function(str) {
            quiet_send('Trustkit.verify1: ' + str);
            return true;
        };
        Activity.verify.overload('java.lang.String', 'java.security.cert.X509Certificate').implementation = function(str) {
            quiet_send('Trustkit.verify2: ' + str);
            return true;
        };

        quiet_send('Trustkit pinning')
    } catch (err) {
        quiet_send('Trustkit pinner not found')
    }


});
