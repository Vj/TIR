// Attach-only TLS API observer. It does not replace validation or alter return values.
Java.perform(function () {
  try {
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var init = SSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;",
      "[Ljavax.net.ssl.TrustManager;",
      "java.security.SecureRandom"
    );
    init.implementation = function (keyManagers, trustManagers, random) {
      var names = [];
      if (trustManagers) {
        for (var i = 0; i < trustManagers.length; i++) {
          try { names.push(trustManagers[i].getClass().getName().toString()); }
          catch (_) { names.push("unavailable"); }
        }
      }
      send({ type: "ssl_context_init", trust_managers: names });
      return init.call(this, keyManagers, trustManagers, random);
    };
  } catch (error) {
    send({ type: "hook_unavailable", api: "SSLContext.init", detail: String(error) });
  }

  try {
    var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
    var setVerifier = HttpsURLConnection.setDefaultHostnameVerifier.overload("javax.net.ssl.HostnameVerifier");
    setVerifier.implementation = function (verifier) {
      var name = "null";
      try { if (verifier) name = verifier.getClass().getName().toString(); } catch (_) {}
      send({ type: "default_hostname_verifier", class_name: name });
      return setVerifier.call(this, verifier);
    };
  } catch (error) {
    send({ type: "hook_unavailable", api: "HttpsURLConnection.setDefaultHostnameVerifier", detail: String(error) });
  }

  try {
    var Pinner = Java.use("okhttp3.CertificatePinner");
    Pinner.check.overloads.forEach(function (overload) {
      overload.implementation = function () {
        send({ type: "okhttp_certificate_pinner_check" });
        return overload.apply(this, arguments);
      };
    });
  } catch (_) {
    // OkHttp is optional and may be shaded or obfuscated.
  }
});
