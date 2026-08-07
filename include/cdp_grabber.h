/*
 * cdp_grabber.h — Chrome DevTools Protocol cookie extraction
 */
#ifndef CDP_GRABBER_H
#define CDP_GRABBER_H

/*
 * Launch headless Chrome with remote debugging, connect via WebSocket,
 * send Network.getAllCookies, parse response, write Netscape format.
 *
 * Attempts ports 9222-9230 in order. Kills existing Chrome first.
 *
 * chrome_exe_path: full path to chrome.exe (or NULL to auto-detect from registry)
 * output_path: path to write Netscape-format cookies.txt
 *
 * Returns 0 on success, -1 on failure.
 */
int cdp_grab_cookies(const char *chrome_exe_path, const char *output_path);

#endif /* CDP_GRABBER_H */
