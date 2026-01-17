/**
 * Doxygen Awesome Fragment Copy Button
 * https://github.com/jothepro/doxygen-awesome-css
 * MIT License
 * 
 * Adds a copy button to code fragments
 */

class DoxygenAwesomeFragmentCopyButton extends HTMLElement {
    static copyIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
    
    static successIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
    
    static title = "Copy to clipboard";
    static titleSuccess = "Copied!";
    static timeout = 2000;

    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        
        const style = document.createElement('style');
        style.textContent = `
            :host {
                position: absolute;
                top: 8px;
                right: 8px;
            }
            
            button {
                background: var(--fragment-background, #f8f9fa);
                border: 1px solid var(--separator-color, #e5e7eb);
                border-radius: 4px;
                padding: 4px 8px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
                color: var(--page-secondary-foreground-color, #6b7280);
                transition: all 0.15s ease-in-out;
                opacity: 0;
            }
            
            :host(:hover) button,
            :host-context(.fragment:hover) button {
                opacity: 1;
            }
            
            button:hover {
                background: var(--menu-focus-background, #e5e7eb);
                color: var(--page-foreground-color, #1f2937);
            }
            
            button.success {
                color: #10b981;
            }
            
            svg {
                width: 14px;
                height: 14px;
            }
            
            .success-icon {
                display: none;
            }
            
            button.success .copy-icon {
                display: none;
            }
            
            button.success .success-icon {
                display: block;
            }
        `;
        
        const button = document.createElement('button');
        button.title = DoxygenAwesomeFragmentCopyButton.title;
        button.innerHTML = `
            <span class="copy-icon">${DoxygenAwesomeFragmentCopyButton.copyIcon}</span>
            <span class="success-icon">${DoxygenAwesomeFragmentCopyButton.successIcon}</span>
        `;
        
        button.addEventListener('click', () => {
            this.copyToClipboard(button);
        });
        
        this.shadowRoot.appendChild(style);
        this.shadowRoot.appendChild(button);
    }
    
    copyToClipboard(button) {
        const fragment = this.closest('.fragment');
        if (!fragment) return;
        
        const lines = fragment.querySelectorAll('.line');
        let text = '';
        
        lines.forEach((line, index) => {
            // Remove line numbers if present
            let lineText = line.textContent;
            text += lineText + (index < lines.length - 1 ? '\n' : '');
        });
        
        navigator.clipboard.writeText(text).then(() => {
            button.classList.add('success');
            button.title = DoxygenAwesomeFragmentCopyButton.titleSuccess;
            
            setTimeout(() => {
                button.classList.remove('success');
                button.title = DoxygenAwesomeFragmentCopyButton.title;
            }, DoxygenAwesomeFragmentCopyButton.timeout);
        }).catch(err => {
            console.error('Failed to copy: ', err);
        });
    }
}

// Initialize: Add copy buttons to all fragments
function initFragmentCopyButtons() {
    document.querySelectorAll('.fragment').forEach(fragment => {
        if (!fragment.querySelector('doxygen-awesome-fragment-copy-button')) {
            fragment.style.position = 'relative';
            const copyButton = document.createElement('doxygen-awesome-fragment-copy-button');
            fragment.appendChild(copyButton);
        }
    });
}

// Register the custom element
customElements.define('doxygen-awesome-fragment-copy-button', DoxygenAwesomeFragmentCopyButton);

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initFragmentCopyButtons);
} else {
    initFragmentCopyButtons();
}
