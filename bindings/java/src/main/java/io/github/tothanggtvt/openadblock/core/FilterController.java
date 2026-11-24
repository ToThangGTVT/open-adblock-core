package io.github.tothanggtvt.openadblock.core;

/** Filter lists and scriptlet resources. Changes apply to new requests immediately. */
public interface FilterController {
    /**
     * Compiles and (when {@code apply}) installs filter lists in AdGuard/uBlock syntax.
     *
     * @param dnsRules lists used only by the DNS/domain matcher
     * @param browserRules lists used only on decrypted HTTPS (paths, cosmetic, scriptlets)
     * @param customRules the user's own rules, used by both
     * @param apply {@code false} only validates
     * @return JSON report {@code {"loaded":n,"ignored":n,"errors":[{"line":n,"message":".."}]}}
     */
    String replaceRules(String dnsRules, String browserRules, String customRules, boolean apply);

    /**
     * Installs AdGuard Scriptlets {@code scriptlets.corelibs.json} / {@code redirects.json}
     * (either may be empty).
     *
     * @return {@code {"scriptlets":n,"redirects":n,"skipped":n}} or {@code {"error":".."}}; on
     *     error the previous set stays active
     */
    String setResources(String scriptlets, String redirects);
}
