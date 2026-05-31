const { pathname, hostname, href } = window.location;

if (pathname.startsWith('/z')) {
  window.location.href = href.replace('/z', '/a');
}

// if (
//   (hostname === 'web.splus.ir' || hostname === 'webzstage13.talkapp.ir') && !localStorage.getItem('sp-global-state') && !localStorage.getItem('tt-global-state')
// ) {
//   window.location.href = `https://${hostname}/`;
// }
