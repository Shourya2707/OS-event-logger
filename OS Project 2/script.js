// Real-Time OS Security Event Logger Documentation JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Smooth scrolling for navigation links
    const navLinks = document.querySelectorAll('nav a');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetElement = document.querySelector(targetId);
            
            if (targetElement) {
                // Smooth scroll to target
                window.scrollTo({
                    top: targetElement.offsetTop - 70, // Account for sticky nav
                    behavior: 'smooth'
                });
                
                // Update URL without page reload
                history.pushState(null, null, targetId);
            }
        });
    });
    
    // Highlight active section in navigation
    const sections = document.querySelectorAll('section');
    
    function highlightActiveSection() {
        const scrollPosition = window.scrollY;
        
        sections.forEach(section => {
            const sectionTop = section.offsetTop - 100;
            const sectionHeight = section.offsetHeight;
            const sectionId = '#' + section.getAttribute('id');
            
            if (scrollPosition >= sectionTop && scrollPosition < sectionTop + sectionHeight) {
                // Remove active class from all links
                navLinks.forEach(link => {
                    link.classList.remove('active');
                });
                
                // Add active class to current section link
                const activeLink = document.querySelector(`nav a[href="${sectionId}"]`);
                if (activeLink) {
                    activeLink.classList.add('active');
                }
            }
        });
    }
    
    // Add active class to navigation links based on scroll position
    window.addEventListener('scroll', highlightActiveSection);
    
    // Initialize active section
    highlightActiveSection();
    
    // Toggle code snippet visibility
    const codeSnippets = document.querySelectorAll('.code-snippet');
    
    codeSnippets.forEach(snippet => {
        // Add a header to code snippets
        const header = document.createElement('div');
        header.className = 'code-header';
        header.innerHTML = '<span>Code Example</span>';
        
        // Add copy button
        const copyButton = document.createElement('button');
        copyButton.className = 'copy-button';
        copyButton.textContent = 'Copy';
        copyButton.addEventListener('click', function() {
            const code = snippet.querySelector('code').textContent;
            navigator.clipboard.writeText(code).then(function() {
                copyButton.textContent = 'Copied!';
                setTimeout(function() {
                    copyButton.textContent = 'Copy';
                }, 2000);
            }).catch(function(err) {
                console.error('Could not copy text: ', err);
            });
        });
        
        header.appendChild(copyButton);
        snippet.insertBefore(header, snippet.firstChild);
    });
    
    // Add CSS for the code header and copy button
    const style = document.createElement('style');
    style.textContent = `
        .code-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 0.5rem 1rem;
            background-color: #34495e;
            border-radius: 6px 6px 0 0;
            font-size: 0.9rem;
            color: white;
        }
        
        .copy-button {
            padding: 0.25rem 0.5rem;
            background-color: #3498db;
            border: none;
            border-radius: 4px;
            color: white;
            cursor: pointer;
            transition: background-color 0.3s;
        }
        
        .copy-button:hover {
            background-color: #2980b9;
        }
        
        .code-snippet pre {
            margin-top: 0;
            border-top-left-radius: 0;
            border-top-right-radius: 0;
        }
        
        nav a.active {
            background-color: rgba(255, 255, 255, 0.3);
            font-weight: bold;
        }
    `;
    document.head.appendChild(style);
}); 