/**
 * Doxygen Awesome Interactive Table of Contents
 * https://github.com/jothepro/doxygen-awesome-css
 * MIT License
 * 
 * Highlights the current section in the table of contents while scrolling
 */

class DoxygenAwesomeInteractiveToc {
    static init() {
        const toc = document.querySelector('.contents-toc, #toc');
        if (!toc) return;
        
        const tocLinks = toc.querySelectorAll('a[href^="#"]');
        if (tocLinks.length === 0) return;
        
        const headings = [];
        tocLinks.forEach(link => {
            const id = link.getAttribute('href').substring(1);
            const heading = document.getElementById(id);
            if (heading) {
                headings.push({ element: heading, link: link });
            }
        });
        
        if (headings.length === 0) return;
        
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const heading = headings.find(h => h.element === entry.target);
                    if (heading) {
                        tocLinks.forEach(l => l.classList.remove('active'));
                        heading.link.classList.add('active');
                    }
                }
            });
        }, {
            rootMargin: '-20% 0px -80% 0px'
        });
        
        headings.forEach(heading => {
            observer.observe(heading.element);
        });
    }
}

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => DoxygenAwesomeInteractiveToc.init());
} else {
    DoxygenAwesomeInteractiveToc.init();
}
