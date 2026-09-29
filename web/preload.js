'use strict';

// Keep the shell hidden until the hosted session check chooses the right view.
if (location.hostname.endsWith('.onrender.com')) {
  document.documentElement.classList.add('hosted-preload');
}
