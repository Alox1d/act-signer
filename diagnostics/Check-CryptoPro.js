// Independent Windows Script Host probe. ASCII, compatible with JScript 5.x.
// No certificate identities, key access, signing or store changes.
(function () {
    function line(text) {
        WScript.StdOut.WriteLine(text);
    }
    function hex(number) {
        var value = (number >>> 0).toString(16).toUpperCase();
        while (value.length < 8) { value = "0" + value; }
        return "0x" + value;
    }
    function error(stage, exception) {
        line(stage + ".status=ERROR");
        line(stage + ".error.hresult=" + hex(exception.number));
        // Description and message may contain personal paths or provider data.
    }
    var allowed = {
        CurrentUserReadOnly: true,
        ContainerReadOnly: true,
        DefaultOpen: true,
        CurrentUserLocationOnly: true,
        CurrentUserMaximumAllowed: true,
        MemoryReadOnly: true
    };
    if (WScript.Arguments.length !== 1 || allowed[WScript.Arguments.Item(0)] !== true) {
        line("Worker.status=INVALID_ARGUMENT");
        WScript.Quit(2);
        return;
    }
    var probeCase = WScript.Arguments.Item(0);
    line("Probe.Case=" + probeCase);
    line("Probe.Host=CScript.JScript");
    line("Runtime.WSH=" + WScript.Version);
    line("Runtime.JScript=" + ScriptEngineMajorVersion() + "." + ScriptEngineMinorVersion() + "." + ScriptEngineBuildVersion());
    try {
        var shell = new ActiveXObject("WScript.Shell");
        var architecture = String(shell.Environment("Process")("PROCESSOR_ARCHITECTURE")).toUpperCase();
        var architectures = { AMD64: "x64", X86: "x86", ARM64: "arm64", ARM: "arm" };
        line("Probe.ProcessArchitecture=" + (architectures[architecture] || "unknown"));
        shell = null;
    } catch (environmentError) { error("Runtime.Architecture", environmentError); }
    var store = null;
    var opened = false;
    var failed = false;
    var stage = "Create";
    try {
        store = new ActiveXObject("CAdESCOM.Store");
        line("Create.status=OK");
        stage = "Open";
        switch (probeCase) {
        case "CurrentUserReadOnly": store.Open(2, "My", 0); break;
        case "ContainerReadOnly": store.Open(100, "My", 0); break;
        case "DefaultOpen": store.Open(); break;
        case "CurrentUserLocationOnly": store.Open(2); break;
        case "CurrentUserMaximumAllowed": store.Open(2, "My", 2); break;
        case "MemoryReadOnly": store.Open(0, "My", 0); break;
        }
        opened = true;
        line("Open.status=OK");
        stage = "Certificates.Count";
        var count = store.Certificates.Count;
        line("Certificates.Count=" + count);
    } catch (probeError) {
        failed = true;
        error(stage, probeError);
    } finally {
        if (opened) {
            try {
                store.Close();
                line("Close.status=OK");
            } catch (closeError) {
                failed = true;
                error("Close", closeError);
            }
        }
        store = null;
    }
    WScript.Quit(failed ? 1 : 0);
}());
