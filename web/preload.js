'use strict';

// Keep the shell hidden until the hosted session check chooses the right view.
// Applies to Render (primary host) and GitHub Pages (static CDN front-end).
if (location.hostname.endsWith('.onrender.com') || location.hostname.endsWith('.github.io')) {
  document.documentElement.classList.add('hosted-preload');
}
