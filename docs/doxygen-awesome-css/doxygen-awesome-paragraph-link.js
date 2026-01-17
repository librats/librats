/**
 * Doxygen Awesome Paragraph Link
 * https://github.com/jothepro/doxygen-awesome-css
 * MIT License
 * 
 * Adds anchor links to headings for easy linking
 */

class DoxygenAwesomeParagraphLink extends HTMLElement {
    static icon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path></svg>`;

    constructor() {
        super();
        this.attachShadow({ mode: 'open' });
        
        const style = document.createElement('style');
        style.textContent = `
            :host {
                display: inline-block;
                margin-left: 8px;
                vertical-align: middle;
                opacity: 0;
                transition: opacity 0.15s ease-in-out;
            }
            
            :host-context(:hover) {
                opacity: 1;
            }
            
            a {
                display: flex;
                align-items: center;
                justify-content: center;
                color: var(--primary-color, #3b82f6);
                text-decoration: none;
            }
            
            a:hover {
                color: var(--primary-dark-color, #2563eb);
            }
            
            svg {
                width: 16px;
                height: 16px;
            }
        `;
        
        const link = document.createElement('a');
        link.innerHTML = DoxygenAwesomeParagraphLink.icon;
        link.title = 'Permalink';
        
        this.shadowRoot.appendChild(style);
        this.shadowRoot.appendChild(link);
    }
    
    connectedCallback() {
        const link = this.shadowRoot.querySelector('a');
        const heading = this.closest('h1, h2, h3, h4, h5, h6, .memtitle');
        
        if (heading) {
            // Find the anchor element
            const anchor = heading.querySelector('a[id], a[name]') || heading.closest('[id]');
            if (anchor) {
                const id = anchor.id || anchor.name || anchor.getAttribute('id');
                if (id) {
                    link.href = '#' + id;
                }
            }
        }
    }
}

// Initialize: Add paragraph links to headings
function initParagraphLinks() {
    const selectors = [
        '.contents h1',
        '.contents h2', 
        '.contents h3',
        '.contents h4',
        '.contents h5',
        '.contents h6',
        '.memtitle'
    ];
    
    document.querySelectorAll(selectors.join(', ')).forEach(heading => {
        if (!heading.querySelector('doxygen-awesome-paragraph-link')) {
            const paragraphLink = document.createElement('doxygen-awesome-paragraph-link');
            heading.appendChild(paragraphLink);
        }
    });
}

// Register the custom element
customElements.define('doxygen-awesome-paragraph-link', DoxygenAwesomeParagraphLink);

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initParagraphLinks);
} else {
    initParagraphLinks();
}
