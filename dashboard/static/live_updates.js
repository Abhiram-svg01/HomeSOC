
/* ======================================================
   HomeSOC — Automatic Dashboard Updates
   Polling interval: 15 seconds
   ====================================================== */

(() => {
    "use strict";

    const REFRESH_INTERVAL = 15000;

    let isUpdating = false;

    // Prevent duplicate refresh engines.
    if (window.homeSOCUpdatesStarted) {
        return;
    }

    window.homeSOCUpdatesStarted = true;

    async function refreshDashboard() {

        // Avoid unnecessary updates in background tabs.
        if (document.hidden || isUpdating) {
            return;
        }

        isUpdating = true;

        try {
            // Request the current dashboard page.
            // Existing search and severity filters are preserved.
            const response = await fetch(
                window.location.href,
                {
                    method: "GET",
                    cache: "no-store"
                }
            );

            if (!response.ok) {
                throw new Error(
                    "Dashboard request failed: " +
                    response.status
                );
            }

            const html = await response.text();

            const parser = new DOMParser();

            const updatedDocument =
                parser.parseFromString(
                    html,
                    "text/html"
                );

            // Refresh metrics and incident tables.
            const selectors = [
                ".summary-grid",
                ".table-wrapper",
                ".empty-state"
            ];

            let changedSections = 0;

            for (const selector of selectors) {

                const currentElements =
                    document.querySelectorAll(selector);

                const updatedElements =
                    updatedDocument.querySelectorAll(selector);

                // Only replace matching sections.
                if (
                    currentElements.length !==
                    updatedElements.length
                ) {
                    continue;
                }

                currentElements.forEach(
                    (currentElement, index) => {

                        const updatedElement =
                            updatedElements[index];

                        if (
                            currentElement.innerHTML !==
                            updatedElement.innerHTML
                        ) {
                            currentElement.replaceWith(
                                updatedElement
                            );

                            changedSections++;
                        }
                    }
                );
            }

            if (changedSections > 0) {
                console.log(
                    "[HomeSOC] Dashboard updated:",
                    changedSections,
                    "sections"
                );
            }

        } catch (error) {
            console.warn(
                "[HomeSOC] Automatic update failed:",
                error.message
            );

        } finally {
            isUpdating = false;
        }
    }

    // Check every 15 seconds.
    setInterval(
        refreshDashboard,
        REFRESH_INTERVAL
    );

    // Check when returning to the browser tab.
    document.addEventListener(
        "visibilitychange",
        () => {
            if (!document.hidden) {
                refreshDashboard();
            }
        }
    );

    console.log(
        "[HomeSOC] Automatic update engine initialized."
    );

})();
