// ==========================================================================
// WebScanPro — Enterprise Frontend Utilities & Interactions
// ==========================================================================

document.addEventListener("DOMContentLoaded", function () {
    // 1. Initialize Lucide Icons if loaded
    if (window.lucide && typeof window.lucide.createIcons === "function") {
        try {
            window.lucide.createIcons();
        } catch (e) {
            console.warn("Lucide icons init warning:", e);
        }
    }

    // 2. Initialize Bootstrap Tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // 3. Sidebar Toggle (Mobile & Desktop Collapse)
    const sidebarToggleBtn = document.getElementById("sidebarToggleBtn");
    const sidebar = document.getElementById("sidebarNav");
    const backdrop = document.getElementById("sidebarBackdrop");
    const mainWrapper = document.querySelector(".main-wrapper");

    if (sidebarToggleBtn && sidebar) {
        sidebarToggleBtn.addEventListener("click", function () {
            if (window.innerWidth <= 992) {
                // Mobile Drawer
                sidebar.classList.toggle("mobile-open");
                if (backdrop) backdrop.classList.toggle("active");
            } else {
                // Desktop Collapse Toggle
                document.body.classList.toggle("sidebar-collapsed");
            }
        });

        if (backdrop) {
            backdrop.addEventListener("click", function () {
                sidebar.classList.remove("mobile-open");
                backdrop.classList.remove("active");
            });
        }
    }

    // 4. Command Palette (Cmd+K / Ctrl+K) Interaction
    const cmdModalEl = document.getElementById("cmdPaletteModal");
    const cmdInput = document.getElementById("cmdInput");
    const cmdList = document.getElementById("cmdList");

    if (cmdModalEl && cmdInput && cmdList) {
        const cmdModal = new bootstrap.Modal(cmdModalEl);

        // Global Shortcut
        window.addEventListener("keydown", function (e) {
            if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
                e.preventDefault();
                cmdModal.show();
            }
        });

        cmdModalEl.addEventListener("shown.bs.modal", function () {
            cmdInput.focus();
            cmdInput.value = "";
            filterCmdItems("");
        });

        cmdInput.addEventListener("input", function () {
            filterCmdItems(this.value.toLowerCase().trim());
        });

        function filterCmdItems(query) {
            const items = cmdList.querySelectorAll("li");
            items.forEach(li => {
                const text = li.innerText.toLowerCase();
                li.style.display = (!query || text.includes(query)) ? "" : "none";
            });
        }
    }

    // 5. Theme Toggle Handler with LocalStorage & Visual Switch
    const themeToggleBtn = document.getElementById("themeToggleBtn");
    const themeToggleIcon = document.getElementById("themeToggleIcon");

    function applyTheme(theme, showToast) {
        const isLight = theme === "light";
        document.documentElement.setAttribute("data-bs-theme", isLight ? "light" : "dark");
        document.documentElement.setAttribute("data-theme", isLight ? "light" : "dark");
        try {
            localStorage.setItem("webscanpro_theme", isLight ? "light" : "dark");
        } catch (e) {}

        if (themeToggleIcon) {
            if (isLight) {
                themeToggleIcon.className = "bi bi-sun-fill text-warning";
            } else {
                themeToggleIcon.className = "bi bi-moon-stars text-info";
            }
        }
        if (themeToggleBtn) {
            themeToggleBtn.setAttribute("title", isLight ? "Switch to Cyber Dark Mode" : "Switch to Light Mode");
        }

        if (showToast) {
            showNotificationToast(
                isLight ? "Light Mode Active" : "Cyber Dark Mode Active",
                isLight ? "Clean Slate Light theme applied." : "Cyber Dark theme applied."
            );
        }

        // Dispatch custom event for any charts or dynamic listeners
        window.dispatchEvent(new CustomEvent("themeChanged", { detail: { theme: isLight ? "light" : "dark" } }));
    }

    // Initialize state on DOM load
    let currentTheme = "dark";
    try {
        currentTheme = localStorage.getItem("webscanpro_theme") || "dark";
    } catch (e) {}
    applyTheme(currentTheme, false);

    if (themeToggleBtn) {
        themeToggleBtn.addEventListener("click", function () {
            const activeTheme = document.documentElement.getAttribute("data-bs-theme") || "dark";
            const newTheme = activeTheme === "dark" ? "light" : "dark";
            applyTheme(newTheme, true);
        });
    }
});

// Toast notification helper
function showNotificationToast(title, message) {
    let container = document.getElementById("toastContainer");
    if (!container) {
        container = document.createElement("div");
        container.id = "toastContainer";
        container.style.position = "fixed";
        container.style.bottom = "20px";
        container.style.right = "20px";
        container.style.zIndex = "9999";
        document.body.appendChild(container);
    }

    const isLight = document.documentElement.getAttribute("data-bs-theme") === "light";
    const toast = document.createElement("div");
    toast.className = "card-saas p-3 mb-2 shadow-lg";
    toast.style.background = isLight ? "#FFFFFF" : "#151F35";
    toast.style.border = isLight ? "1px solid #CBD5E1" : "1px solid rgba(56, 189, 248, 0.3)";
    toast.style.maxWidth = "320px";
    toast.style.animation = "fadeIn 0.2s ease";
    toast.innerHTML = `
        <div class="d-flex align-items-center gap-2">
            <i class="bi bi-shield-check ${isLight ? 'text-primary' : 'text-cyan'} fs-5"></i>
            <div>
                <div class="fw-bold ${isLight ? 'text-dark' : 'text-white'} small">${title}</div>
                <div class="${isLight ? 'text-muted' : 'text-secondary'}" style="font-size: 0.78rem;">${message}</div>
            </div>
        </div>
    `;
    container.appendChild(toast);
    setTimeout(() => {
        toast.style.opacity = "0";
        setTimeout(() => toast.remove(), 300);
    }, 3200);
}
