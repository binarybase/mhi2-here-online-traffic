/*
 * PatchOnlineTraffic — surgical bytecode patch for online-traffic in Croatia.
 *
 * Target bundle : eso/bundles/service.onlinetraffic_1.0.0.20181126-1131.jar
 *
 * Two independent, additive patches (javassist, no full recompile):
 *
 *  (1) HR->SI session remap  [always applied]
 *      class  : de.eso.mib.online.onlinetraffic.event.GetNewDataResultEvent
 *      method : createTrafficSession(OnlineTrafficImpl, String currentCountry,
 *                                    String destCountry)
 *      why    : the VWG/Audi (TomTom) backend returns HTTP 502 for
 *               createTrafficSession whenever the session country is "HR"
 *               (Croatia). Remapping ONLY "HR" -> a working neighbour ("SI")
 *               for the session-init request lets Audi mint a valid session
 *               object (duration + update frequencies), which we then reuse.
 *
 *  (2) Data-source runtime TOGGLE  [applied when redirectUrl != "none"]
 *      class  : de.eso.mib.online.onlinetraffic.impl.TrafficSession
 *      methods: getURL() and getEncryptionKey()  (bodies rewritten)
 *      why    : the patch is installed PERMANENTLY. Which backend is used is
 *               decided per request at read-time by the presence of a flag
 *               file (default /mnt/persist/traffic_backend_here):
 *                 - flag PRESENT  -> getURL() returns OUR on-device backend
 *                   (native C++ HTTP server on uap0) and getEncryptionKey()
 *                   returns null, so request-writer/response-reader take the
 *                   plaintext gzip(XML)/raw-TPEG path.
 *                 - flag ABSENT   -> getURL() returns the real TomTom url from
 *                   the session properties and getEncryptionKey() returns the
 *                   real aeskey, i.e. behaviour is identical to the stock jar.
 *               The constructor is left untouched (real url + key stay stored),
 *               so toggling needs no JVM restart: touch/rm the flag file.
 *
 * All other bytes of the jar are left byte-for-byte identical.
 *
 * Usage:
 *   java -cp javassist.jar:. PatchOnlineTraffic <in.jar> <out.jar> \
 *        [remapTo=SI] [redirectUrl=http://10.173.189.1:8099/traffic|none] \
 *        [captureLatLon=lat,lon|none] [deps=...|none] \
 *        [flagFile=/mnt/persist/traffic_backend_here]
 */
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtConstructor;
import javassist.CtMethod;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class PatchOnlineTraffic {

    private static final String EVENT_CLASS =
            "de.eso.mib.online.onlinetraffic.event.GetNewDataResultEvent";
    private static final String EVENT_METHOD = "createTrafficSession";

    private static final String SESSION_CLASS =
            "de.eso.mib.online.onlinetraffic.impl.TrafficSession";

    private static final String WRITER_CLASS =
            "de.eso.mib.online.onlinetraffic.impl.TrafficProviderResponseWriter";
    private static final String WRITER_METHOD = "getXMLLocatablePosition";

    private static final String DEFAULT_REDIRECT = "http://10.173.189.1:8099/traffic";

    // Presence of this file (on the JVM host) selects the HERE backend at
    // request time; absence keeps the stock TomTom path. No JVM restart needed.
    private static final String DEFAULT_FLAG_FILE = "/mnt/persist/traffic_backend_here";

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: PatchOnlineTraffic <in.jar> <out.jar> "
                    + "[remapTo=SI] [redirectUrl=" + DEFAULT_REDIRECT + "|none] "
                    + "[captureLatLon=lat,lon|none] [deps=jar1" + java.io.File.pathSeparator + "dir2|none] "
                    + "[flagFile=" + DEFAULT_FLAG_FILE + "]");
            System.exit(2);
        }
        String inJar = args[0];
        String outJar = args[1];
        String remapTo = (args.length > 2 && args[2].length() > 0) ? args[2] : "SI";
        String redirectUrl = (args.length > 3 && args[3].length() > 0) ? args[3] : DEFAULT_REDIRECT;
        String captureLatLon = (args.length > 4 && args[4].length() > 0) ? args[4] : "none";
        String deps = (args.length > 5 && args[5].length() > 0 && !"none".equalsIgnoreCase(args[5])) ? args[5] : "";
        String flagFile = (args.length > 6 && args[6].length() > 0) ? args[6] : DEFAULT_FLAG_FILE;
        if (flagFile.indexOf('"') >= 0 || flagFile.indexOf('\\') >= 0) {
            System.err.println("flagFile contains illegal characters: " + flagFile);
            System.exit(2);
        }

        if (remapTo.length() != 2) {
            System.err.println("remapTo must be a 2-letter ISO country code, got: " + remapTo);
            System.exit(2);
        }
        boolean doRedirect = !"none".equalsIgnoreCase(redirectUrl);
        boolean doCapture = !"none".equalsIgnoreCase(captureLatLon);

        // Parse capture lat,lon (capture mode forces every <loc> to a fixed busy
        // Slovenian point so a driveway poll returns real non-empty TPEG).
        String capLat = "", capLon = "";
        if (doCapture) {
            int comma = captureLatLon.indexOf(',');
            if (comma <= 0) {
                System.err.println("captureLatLon must be \"lat,lon\", got: " + captureLatLon);
                System.exit(2);
            }
            capLat = captureLatLon.substring(0, comma).trim();
            capLon = captureLatLon.substring(comma + 1).trim();
            try { Double.parseDouble(capLat); Double.parseDouble(capLon); }
            catch (NumberFormatException nfe) {
                System.err.println("captureLatLon not numeric: " + captureLatLon);
                System.exit(2);
            }
        }

        ClassPool cp = new ClassPool(true); // true => append JRE system path (String, Properties, ...)
        cp.insertClassPath(inJar);          // resolve OnlineTrafficImpl / OTEvent etc.
        // Extra dependency classpath (capture mode needs nanoxml.XMLElement,
        // org.dsi.ifc.online.LocatablePosition, de.audi.osgi.util.* which live in
        // sibling bundles / the runtime classpath, not in the target jar).
        for (String p : deps.split(java.io.File.pathSeparator)) {
            if (p.length() > 0) { cp.insertClassPath(p); }
        }

        // Map of "internal/name.class" -> patched bytecode.
        Map patched = new HashMap();

        // ── Patch (1): createTrafficSession — offline session mint + HR->SI ────
        // $1=OnlineTrafficImpl tr, $2=currentCountry, $3=destCountry.
        // When the HERE flag file is present we build the TrafficSession LOCALLY
        // from a synthetic <trafficSessionResponse> and return BEFORE the core
        // getConnectionFactory().http_method("GET","traffic-online_v1",...) call.
        // That core call resolves the service name via Audi's serviceList
        // (service discovery), which fails with ERRORCODE_CONNECTIVITY_ERROR when
        // Audi Connect's backend is unreachable — the exact "createSession
        // CoreServiceException" regression. Minting the session offline makes the
        // online-traffic path independent of Audi Connect (data is then POSTed to
        // our backend, whose URL/key TrafficSession.getURL/getEncryptionKey
        // already return when the flag is present). Flag absent => stock path.
        {
            CtClass cc = cp.get(EVENT_CLASS);
            if (cc.isFrozen()) cc.defrost();
            CtMethod m = cc.getDeclaredMethod(EVENT_METHOD);
            String bypass = "";
            if (doRedirect) {
                if (redirectUrl.indexOf('"') >= 0 || redirectUrl.indexOf('\\') >= 0) {
                    System.err.println("redirectUrl contains illegal characters: " + redirectUrl);
                    System.exit(2);
                }
                // Minimal valid session XML. getURL()/getEncryptionKey() are
                // overridden (Patch 2) to our backend + null key when the flag is
                // present, so only a well-formed root + a <url> fallback matter.
                String synthXml =
                        "<trafficSessionResponse><url>" + redirectUrl + "</url>"
                      + "<sessionId>LOCAL</sessionId></trafficSessionResponse>";
                bypass =
                    "  if (new java.io.File(\"" + flagFile + "\").exists()) {"
                  + "    de.eso.mib.online.onlinetraffic.impl.TrafficSession __ts ="
                  + "        new de.eso.mib.online.onlinetraffic.impl.TrafficSession("
                  + "            $1.getsessionDuration(),"
                  + "            (java.io.Reader) new java.io.StringReader(\"" + synthXml + "\"));"
                  + "    de.eso.mib.online.onlinetraffic.Activator.getOnlineTrafficImpl().setTrafficSession(__ts);"
                  + "    de.eso.mib.online.onlinetraffic.Activator.getOnlineTrafficImpl().setWaitIntervall(0L);"
                  + "    $1.setSessionHTTPCode(\"200\");"
                  + "    return;"
                  + "  }";
            }
            String snippet =
                    "{" + bypass
                  + "  if (\"HR\".equals($2)) { $2 = \"" + remapTo + "\"; }"
                  + "  if (\"HR\".equals($3)) { $3 = \"" + remapTo + "\"; } }";
            m.insertBefore(snippet);
            patched.put(EVENT_CLASS.replace('.', '/') + ".class", cc.toBytecode());
            System.out.println("OK (1): createTrafficSession patched (HR->" + remapTo
                    + (doRedirect ? "; offline session mint when flag=" + flagFile : "") + ")");
        }

        // ── Patch (2): runtime TOGGLE — override getURL + getEncryptionKey ────
        // The patch is permanent; the backend is chosen per request by the
        // presence of `flagFile`. Flag absent => stock TomTom behaviour
        // (real url + real key). Flag present => our backend + null key.
        if (doRedirect) {
            if (redirectUrl.indexOf('"') >= 0 || redirectUrl.indexOf('\\') >= 0) {
                System.err.println("redirectUrl contains illegal characters: " + redirectUrl);
                System.exit(2);
            }
            CtClass cc = cp.get(SESSION_CLASS);
            if (cc.isFrozen()) cc.defrost();

            // getURL(): flag present -> our backend; else the stored TomTom url.
            // Preserve the original "?tid="/"&tid=" suffix logic either way.
            CtMethod gurl = cc.getDeclaredMethod("getURL");
            gurl.setBody(
                    "{ String __u;"
                  + "  if (new java.io.File(\"" + flagFile + "\").exists()) {"
                  + "      __u = \"" + redirectUrl + "\"; }"
                  + "  else { __u = this.sessionProperties.getProperty(\"url\"); }"
                  + "  if (__u.indexOf(\"?\") == -1) {"
                  + "      __u = __u + \"?tid=\" + String.valueOf(this.getTid()); }"
                  + "  else { __u = __u + \"&tid=\" + String.valueOf(this.getTid()); }"
                  + "  return new java.net.URL(__u); }");

            // getEncryptionKey(): flag present -> null (plaintext); else real key.
            CtMethod gkey = cc.getDeclaredMethod("getEncryptionKey");
            gkey.setBody(
                    "{ if (new java.io.File(\"" + flagFile + "\").exists()) { return null; }"
                  + "  return this.aeskey; }");

            patched.put(SESSION_CLASS.replace('.', '/') + ".class", cc.toBytecode());
            System.out.println("OK (2): runtime toggle installed in TrafficSession "
                    + "(flag=" + flagFile + " -> url=" + redirectUrl + " + null key)");
        } else {
            System.out.println("SKIP (2): redirect disabled (redirectUrl=none)");
        }

        // ── Patch (3): CAPTURE mode — force every <loc> to a fixed SI point ────
        // Used ONLY to obtain a real non-empty TPEG sample from the driveway:
        // keeps the real TomTom data path (redirectUrl=none, key intact) but
        // rewrites getXMLLocatablePosition so the getMessages request always asks
        // about a busy Slovenian coordinate the SI session covers. Revert after.
        if (doCapture) {
            CtClass cc = cp.get(WRITER_CLASS);
            if (cc.isFrozen()) cc.defrost();
            CtMethod m = cc.getDeclaredMethod(WRITER_METHOD);
            // signature: XMLElement getXMLLocatablePosition(LocatablePosition loc, int order)
            // $2 = order. getConfigurationElement(name,unit,content) is private (same class).
            String body =
                    "{ nanoxml.XMLElement xl = new nanoxml.XMLElement();"
                  + "  xl.setName(\"loc\");"
                  + "  xl.addChild(this.getConfigurationElement(\"order\", null, \"\" + $2));"
                  + "  xl.addChild(this.getConfigurationElement(\"lat\", null, \"" + capLat + "\"));"
                  + "  xl.addChild(this.getConfigurationElement(\"lon\", null, \"" + capLon + "\"));"
                  + "  xl.addChild(this.getConfigurationElement(\"country\", null, \"" + remapTo + "\"));"
                  + "  return xl; }";
            m.setBody(body);
            patched.put(WRITER_CLASS.replace('.', '/') + ".class", cc.toBytecode());
            System.out.println("OK (3): CAPTURE mode — every <loc> forced to " + capLat + "," + capLon
                    + " country=" + remapTo + " in " + WRITER_METHOD);
        }

        // ── Copy jar verbatim, swapping only the patched class entries ─────────
        // (preserves entry order so META-INF/MANIFEST.MF stays first for OSGi).
        int copied = 0;
        int replaced = 0;
        byte[] buf = new byte[8192];
        try (ZipInputStream zin = new ZipInputStream(new BufferedInputStream(new FileInputStream(inJar)));
             ZipOutputStream zout = new ZipOutputStream(new BufferedOutputStream(new FileOutputStream(outJar)))) {
            ZipEntry e;
            while ((e = zin.getNextEntry()) != null) {
                zout.putNextEntry(new ZipEntry(e.getName()));
                byte[] repl = (byte[]) patched.get(e.getName());
                if (repl != null) {
                    zout.write(repl);
                    replaced++;
                } else {
                    int n;
                    while ((n = zin.read(buf)) > 0) {
                        zout.write(buf, 0, n);
                    }
                }
                zout.closeEntry();
                zin.closeEntry();
                copied++;
            }
        }

        if (replaced != patched.size()) {
            System.err.println("ERROR: expected to replace " + patched.size()
                    + " class entries but replaced " + replaced
                    + " (a target class was not found in the jar)");
            System.exit(1);
        }
        System.out.println("DONE: entries copied = " + copied + ", classes replaced = " + replaced);
        System.out.println("      output = " + outJar);
    }
}
