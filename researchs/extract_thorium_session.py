#!/usr/bin/env python3
import os
import shutil
import asyncio
import base64
import json
import re
import sys
from pathlib import Path

# Paths
THORIUM_PROFILE_DIR = Path.home() / ".config" / "thorium"
TEMP_PROFILE_DIR = Path("/tmp/thorium_temp")
OUTPUT_KEY_FILE = Path("/home/salman/Projects/research/Sorush/soroush-relay/researchs/auth_key.txt")
SCRAPER_KEY_FILE = Path("/home/salman/Projects/python/soroush-scraper/webs/web.splus.ir/logs/auth_key.txt")

try:
    from playwright.async_api import async_playwright
except ImportError:
    print("[ERROR] Playwright is not installed in the python environment.")
    sys.exit(1)

def clean_temp_profile():
    if TEMP_PROFILE_DIR.exists():
        print(f"[Profile] Cleaning up old temporary profile: {TEMP_PROFILE_DIR}")
        shutil.rmtree(TEMP_PROFILE_DIR, ignore_errors=True)

def copy_profile():
    clean_temp_profile()
    print(f"[Profile] Copying Thorium profile from {THORIUM_PROFILE_DIR} to {TEMP_PROFILE_DIR} ...")
    TEMP_PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    
    # We only need IndexedDB, Local Storage, and Preferences. 
    # Copying the whole thorium config can be huge (GBs of Cache/Media Cache).
    # Let's copy selectively!
    src_default = THORIUM_PROFILE_DIR / "Default"
    dest_default = TEMP_PROFILE_DIR / "Default"
    dest_default.mkdir(parents=True, exist_ok=True)
    
    # Copy Preferences and Local State
    for item in ["Preferences", "Local Storage", "IndexedDB", "Web Storage"]:
        src_path = src_default / item
        if src_path.exists():
            dest_path = dest_default / item
            print(f"  - Copying {item} ...")
            if src_path.is_dir():
                shutil.copytree(src_path, dest_path, symlinks=True, ignore=shutil.ignore_patterns("Cache", "Media Cache", "GPUCache"))
            else:
                shutil.copy2(src_path, dest_path)
                
    # Copy Local State from root
    src_local_state = THORIUM_PROFILE_DIR / "Local State"
    if src_local_state.exists():
        shutil.copy2(src_local_state, TEMP_PROFILE_DIR / "Local State")
        
    # Remove LOCK files recursively
    print("[Profile] Deleting leveldb/IndexedDB LOCK files ...")
    for lock_file in TEMP_PROFILE_DIR.glob("**/LOCK"):
        try:
            lock_file.unlink()
        except Exception:
            pass

async def extract_session_for_url(context, url):
    print(f"\n[Browser] Navigating to {url} ...")
    page = await context.new_page()
    try:
        # Navigate and wait a bit
        await page.goto(url, wait_until="domcontentloaded", timeout=10000)
        await asyncio.sleep(2)
        
        print("[Browser] Evaluating IndexedDB & LocalStorage dumper ...")
        db_dump = await page.evaluate("""async () => {
            return new Promise((resolve) => {
                let results = {};
                try {
                    // 1. Read LocalStorage
                    for (let i = 0; i < localStorage.length; i++) {
                        let k = localStorage.key(i);
                        results["LS:" + k] = localStorage.getItem(k);
                    }
                } catch(e) {}
                
                // 2. Read IndexedDB
                if (!window.indexedDB || !window.indexedDB.databases) {
                    resolve(results);
                    return;
                }
                
                window.indexedDB.databases().then((dbs) => {
                    if (dbs.length === 0) {
                        resolve(results);
                        return;
                    }
                    let dbPromises = dbs.map(dbInfo => {
                        return new Promise((resDb) => {
                            let openReq = window.indexedDB.open(dbInfo.name);
                            openReq.onsuccess = (e) => {
                                let db = e.target.result;
                                let storeNames = Array.from(db.objectStoreNames);
                                if (storeNames.length === 0) {
                                    db.close();
                                    resDb();
                                    return;
                                }
                                
                                let tx = db.transaction(storeNames, "readonly");
                                let storePromises = storeNames.map(storeName => {
                                    return new Promise((resStore) => {
                                        let store = tx.objectStore(storeName);
                                        let getAllReq = store.getAll();
                                        let getAllKeysReq = store.getAllKeys();
                                        
                                        getAllReq.onsuccess = () => {
                                            getAllKeysReq.onsuccess = () => {
                                                let keys = getAllKeysReq.result;
                                                let values = getAllReq.result;
                                                for (let i = 0; i < keys.length; i++) {
                                                    let keyStr = typeof keys[i] === 'object' ? JSON.stringify(keys[i]) : keys[i].toString();
                                                    results[`IDB:${dbInfo.name}:${storeName}:${keyStr}`] = values[i];
                                                }
                                                resStore();
                                            };
                                        };
                                        getAllReq.onerror = () => resStore();
                                    });
                                });
                                
                                Promise.all(storePromises).then(() => {
                                    db.close();
                                    resDb();
                                }).catch(() => {
                                    db.close();
                                    resDb();
                                });
                            };
                            openReq.onerror = () => resDb();
                        });
                    });
                    
                    Promise.all(dbPromises).then(() => resolve(results)).catch(() => resolve(results));
                }).catch(() => resolve(results));
            });
        }""")
        
        # Scan for auth keys
        print(f"[SESSION] Scanning {len(db_dump)} dumped storage keys ...")
        for key, val in db_dump.items():
            print(f"  - Key: {key}")
            if "auth_key" in key.lower():
                print(f"    VALUE: {val}")
            session_str = None
            if isinstance(val, str) and (val.startswith("1") or "session" in key.lower()):
                session_str = val
            elif isinstance(val, dict):
                # Print dictionary keys to help identify where authKey is
                print(f"    Dict keys: {list(val.keys())}")
                for k2, v2 in val.items():
                    if isinstance(v2, str) and (v2.startswith("1") or "session" in k2.lower()):
                        session_str = v2
                        break
                    elif "authkey" in k2.lower() and isinstance(v2, dict) and "data" in v2:
                        try:
                            auth_key_hex = bytes(v2["data"]).hex()
                            print(f"[SESSION SUCCESS] Found raw AuthKey in nested dict: {key} -> {k2}")
                            return auth_key_hex
                        except Exception:
                            pass
            
            if session_str and len(session_str) > 260:
                try:
                    s_str = session_str[1:] if session_str.startswith("1") else session_str
                    padding = len(s_str) % 4
                    if padding:
                        s_str += "=" * (4 - padding)
                    decoded = base64.b64decode(s_str)
                    if len(decoded) >= 256:
                        auth_key_hex = decoded[-256:].hex()
                        print(f"[SESSION SUCCESS] Extracted GramJS Session AuthKey from: {key}")
                        return auth_key_hex
                except Exception as ex:
                    pass
    except Exception as e:
        print(f"[Browser Error] Navigation or extraction failed: {e}")
    finally:
        await page.close()
    return None

async def main():
    copy_profile()
    
    print("\n[Browser] Starting headless Thorium browser with copied profile ...")
    async with async_playwright() as pw:
        # Launch persistent context
        context = await pw.chromium.launch_persistent_context(
            user_data_dir=TEMP_PROFILE_DIR,
            executable_path="/usr/bin/thorium-browser",
            headless=True,
            args=["--no-sandbox", "--disable-setuid-sandbox"]
        )
        
        auth_key_hex = None
        # Try both betaweb and production web Splus
        for url in ["https://web.splus.ir", "https://betaweb.splus.ir"]:
            auth_key_hex = await extract_session_for_url(context, url)
            if auth_key_hex:
                break
                
        await context.close()
        
    clean_temp_profile()
    
    if auth_key_hex:
        # Save key
        OUTPUT_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        OUTPUT_KEY_FILE.write_text(auth_key_hex, encoding="utf-8")
        print(f"\n[SUCCESS] Auth Key successfully saved to: {OUTPUT_KEY_FILE}")
        
        # Save to scraper folder too
        SCRAPER_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
        SCRAPER_KEY_FILE.write_text(auth_key_hex, encoding="utf-8")
        print(f"[SUCCESS] Scraper copy saved to: {SCRAPER_KEY_FILE}")
    else:
        print("\n[FAILED] Could not extract any active Soroush session key from Thorium browser.")
        print("[Tip] Make sure you are logged into Soroush Plus Web (web.splus.ir) in your Thorium browser first!")

if __name__ == "__main__":
    asyncio.run(main())
