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
 *  (2) Data-source redirect + null key  [applied when redirectUrl != "none"]
 *      class  : de.eso.mib.online.onlinetraffic.impl.TrafficSession
 *      ctor   : TrafficSession(long duration, java.io.Reader r)
 *      why    : after Audi's session XML is parsed, overwrite the "url"
 *               session property so all subsequent getMessages requests go to
 *               OUR on-device backend (native C++ HTTP server on uap0), and
 *               null the AES key so the wire protocol degrades to plain
 *               gzip(XML) request / raw TPEG response (no AES, no length
 *               prefix). getURL() still appends "?tid=N"; getEncryptionKey()
 *               now returns null, so both request-writer and response-reader
 *               take their no-crypto paths.
 *
 * All other bytes of the jar are left byte-for-byte identical.
 *
 * Usage:
 *   java -cp javassist.jar:. PatchOnlineTraffic <in.jar> <out.jar> \
 *        [remapTo=SI] [redirectUrl=http://10.173.189.1:8099/traffic|none]
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

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: PatchOnlineTraffic <in.jar> <out.jar> "
                    + "[remapTo=SI] [redirectUrl=" + DEFAULT_REDIRECT + "|none] "
                    + "[captureLatLon=lat,lon|none] [deps=jar1" + java.io.File.pathSeparator + "dir2|none]");
            System.exit(2);
        }
        String inJar = args[0];
        String outJar = args[1];
        String remapTo = (args.length > 2 && args[2].length() > 0) ? args[2] : "SI";
        String redirectUrl = (args.length > 3 && args[3].length() > 0) ? args[3] : DEFAULT_REDIRECT;
        String captureLatLon = (args.length > 4 && args[4].length() > 0) ? args[4] : "none";
        String deps = (args.length > 5 && args[5].length() > 0 && !"none".equalsIgnoreCase(args[5])) ? args[5] : "";

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

        // ── Patch (1): HR -> SI remap in createTrafficSession ──────────────────
        {
            CtClass cc = cp.get(EVENT_CLASS);
            if (cc.isFrozen()) cc.defrost();
            CtMethod m = cc.getDeclaredMethod(EVENT_METHOD);
            // $2 = currentCountry, $3 = destCountry  ($0=this, $1=OnlineTrafficImpl)
            String snippet =
                    "{ if (\"HR\".equals($2)) { $2 = \"" + remapTo + "\"; }"
                  + "  if (\"HR\".equals($3)) { $3 = \"" + remapTo + "\"; } }";
            m.insertBefore(snippet);
            patched.put(EVENT_CLASS.replace('.', '/') + ".class", cc.toBytecode());
            System.out.println("OK (1): HR->" + remapTo + " remap injected into " + EVENT_METHOD);
        }

        // ── Patch (2): redirect data URL + null AES key in TrafficSession ──────
        if (doRedirect) {
            if (redirectUrl.indexOf('"') >= 0 || redirectUrl.indexOf('\\') >= 0) {
                System.err.println("redirectUrl contains illegal characters: " + redirectUrl);
                System.exit(2);
            }
            CtClass cc = cp.get(SESSION_CLASS);
            if (cc.isFrozen()) cc.defrost();
            // Constructor: TrafficSession(long duration, java.io.Reader r)
            CtConstructor ctor = cc.getDeclaredConstructor(new CtClass[]{
                    CtClass.longType, cp.get("java.io.Reader") });
            // Runs only on normal (successful) construction. Overwrite the "url"
            // session property so getURL() targets our backend, and null the key
            // so getEncryptionKey() returns null (plaintext wire protocol).
            String snippet =
                    "{ this.sessionProperties.put(\"url\", \"" + redirectUrl + "\");"
                  + "  this.aeskey = null; }";
            ctor.insertAfter(snippet);
            patched.put(SESSION_CLASS.replace('.', '/') + ".class", cc.toBytecode());
            System.out.println("OK (2): redirect url=" + redirectUrl + " + null key injected into TrafficSession ctor");
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
