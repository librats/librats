/**
 * Doxygen Awesome Dark Mode Toggle
 * https://github.com/jothepro/doxygen-awesome-css
 * MIT License
 */

class DoxygenAwesomeDarkModeToggle extends HTMLElement {
    static icon_light = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>`;
    
    static icon_dark = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>`;

    static title_light = "Switch to dark mode";
    static title_dark = "Switch to light mode";

    static prefersColorSchemeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    static localStorageKey = 'doxygen-awesome-dark-mode';

    static init() {
        // Check for saved preference or system preference
        const savedMode = localStorage.getItem(DoxygenAwesomeDarkModeToggle.localStorageKey);
        
        if (savedMode === 'dark' || (savedMode === null && DoxygenAwesomeDarkModeToggle.prefersColorSchemeMediaQuery.matches)) {
            document.documentElement.classList.add('dark-mode');
        }
        
        // Listen for system preference changes
        DoxygenAwesomeDarkModeToggle.prefersColorSchemeMediaQuery.addEventListener('change', (e) => {
            if (localStorage.getItem(DoxygenAwesomeDarkModeToggle.localStorageKey) === null) {
                if (e.matches) {
                    document.documentElement.classList.add('dark-mode');
                } else {
                    document.documentElement.classList.remove('dark-mode');
                }
            }
        });
    }

    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        
        const style = document.createElement('style');
        style.textContent = `
            :host {
                display: inline-block;
            }
            
            button {
                background: transparent;
                border: 1px solid var(--separator-color, #e5e7eb);
                border-radius: 6px;
                padding: 6px 10px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                color: var(--page-secondary-foreground-color, #6b7280);
                transition: all 0.15s ease-in-out;
            }
            
            button:hover {
                background: var(--menu-focus-background, #f3f4f6);
                color: var(--page-foreground-color, #1f2937);
            }
            
            svg {
                width: 18px;
                height: 18px;
            }
            
            .dark-mode-icon {
                display: none;
            }
            
            :host-context(html.dark-mode) .light-mode-icon {
                display: none;
            }
            
            :host-context(html.dark-mode) .dark-mode-icon {
                display: block;
            }
        `;
        
        const button = document.createElement('button');
        button.id = 'dark-mode-toggle';
        button.innerHTML = `
            <span class="light-mode-icon">${DoxygenAwesomeDarkModeToggle.icon_light}</span>
            <span class="dark-mode-icon">${DoxygenAwesomeDarkModeToggle.icon_dark}</span>
        `;
        
        this.updateTitle(button);
        
        button.addEventListener('click', () => {
            this.toggleDarkMode();
            this.updateTitle(button);
        });
        
        this.shadowRoot.appendChild(style);
        this.shadowRoot.appendChild(button);
    }
    
    updateTitle(button) {
        if (document.documentElement.classList.contains('dark-mode')) {
            button.title = DoxygenAwesomeDarkModeToggle.title_dark;
        } else {
            button.title = DoxygenAwesomeDarkModeToggle.title_light;
        }
    }
    
    toggleDarkMode() {
        const isDarkMode = document.documentElement.classList.toggle('dark-mode');
        localStorage.setItem(DoxygenAwesomeDarkModeToggle.localStorageKey, isDarkMode ? 'dark' : 'light');
    }
}

// Initialize dark mode based on saved preference or system preference
DoxygenAwesomeDarkModeToggle.init();

// Register the custom element
customElements.define('doxygen-awesome-dark-mode-toggle', DoxygenAwesomeDarkModeToggle);
