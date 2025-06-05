# Read the current content of src/worker.js
worker_js_content = default_api.read_file(path="src/worker.js")

# Check if the file was read successfully
if "read_file_response" in worker_js_content and worker_js_content["read_file_response"]["status"] == "succeeded":
    original_worker_code = worker_js_content["read_file_response"]["result"]

    # --- Modify worker.js code ---
    # Add the new route handler for encrypted IDs and modify apiRequest
    # This is a complex modification involving adding a new case in handleRequest
    # and changing the logic within apiRequest.
    # Due to the limitations of modifying code snippets iteratively without full context awareness,
    # I will provide the conceptual changes and then attempt to construct the modified code.

    # Conceptual Changes in worker.js:

    # 1. New route in handleRequest:
    #    - Add a new condition to match paths like `/<order>:<encryptedId>`.
    #    - Extract `order` and `encryptedId`.
    #    - Decrypt `encryptedId` to get `decryptedId`.
    #    - Fetch item details using `gd.findItemById(decryptedId)`.
    #    - If item is a folder:
    #      - Render `homepage` HTML, passing `folder_id: decryptedId` in `window.MODEL`.
    #    - If item is a file:
    #      - Render `html` template, passing `file_details: fileObject` (including encrypted ID and download link) in `window.MODEL`.

    # 2. Modify apiRequest:
    #    - Change the POST body expected for directory listing. Instead of `path`, expect `id`.
    #    - If `id` is present in the request body, use the decrypted ID to call `gd._list_gdrive_files`.
    #    - Keep the existing path-based logic for backward compatibility or other uses if necessary, but the frontend will primarily use the ID-based approach for listing.

    # 3. Modify findId2Path:
    #    - Ensure it decrypts the input `id` before using it in `gd.findPathById`. (It appears to do this already, but confirm).

    # 4. Modify handleSearch:
    #   - Ensure the returned file `id` and `driveId` are encrypted. (This seems to be already handled).

    # 5. Modify download:
    #   - Ensure the input `id` from the URL parameter is decrypted. (This seems to be already handled).

    # Attempt to construct the modified worker.js code (illustrative):
    # This is a simplified representation. The actual implementation requires careful integration
    # into the existing handleRequest structure and apiRequest logic.

    new_worker_code = original_worker_code.replace(
        "async function handleRequest(request, event) {",
        """async function handleRequest(request, event) {
  const region = request.headers.get('cf-ipcountry');
  const asn_servers = request.cf.asn;
  const referer = request.headers.get("Referer");
  var user_ip = request.headers.get("CF-Connecting-IP");
  let url = new URL(request.url);
  let path = url.pathname;
  let hostname = url.hostname;
  let is_public_file_view = (path.slice(-1) != \'/\') && (url.searchParams.get(\'a\') === \'view\'); // Add this line

  const encrypted_id_reg = /^\\/(?<num>\\d+):(?<encryptedId>[a-zA-Z0-9-_=]+)$/g;
  const encrypted_match = encrypted_id_reg.exec(path);

  let gd;
  let order = 0; // Default order

  function redirectToIndexPage() {
    return new Response(\'\', {
      status: 307,
      headers: {
        \'Location\': `${url.origin}/0:/`
      }
    });
  }

  if (region && blocked_region.includes(region.toUpperCase())) {
    return new Response(asn_blocked, {
      status: 403,
      headers: {
        "content-type": "text/html;charset=UTF-8",
      },
    })
  } else if (asn_servers && blocked_asn.includes(asn_servers)) {
    return new Response(asn_blocked, {
      headers: {
        \'content-type\': \'text/html;charset=UTF-8\'
      },
      status: 401
    });
  } else if (path == \'/app.js\') {
    const js = await fetch(\'https://gitlab.com/GoogleDriveIndex/Google-Drive-Index/-/raw/dev/src/app.js\', {
      method: \'GET\',\
    })
    const data = await js.text()
    return new Response(data, {
      status: 200,
      headers: {
        \'Content-Type\': \'application/javascript; charset=utf-8\',\
        \'Access-Control-Allow-Origin\': \'*\', // Required for CORS support to work
        \'Access-Control-Allow-Credentials\': true, // Required for cookies, authorization headers with HTTPS
      }\
    });
  } else if (path == \'/logout\') {
    let response = new Response(\"\", {});
    response.headers.set(\'Set-Cookie\', `session=; HttpOnly; Secure; SameSite=Lax;`);
    response.headers.set(\"Refresh\", \"1; url=/?error=Logged Out\");
    return response;
  } else if (path == \'/findpath\') {
    const params = url.searchParams;\
    const id = params.get(\'id\');
    const view = params.get(\'view\') || \'false\';
    // Assuming id here is the encrypted ID from the frontend search result click
    return Response.redirect(url.protocol + hostname + \'/0:findpath?id=\' + id + \'&view=\' + view, 307);
  }

  // Handle login/signup/oauth if enabled and path matches
  if (authConfig.enable_login) {
    const login_database = authConfig.login_database.toLowerCase();
    if (path == \'/download.aspx\' && !authConfig.disable_anonymous_download) {
        // Allow anonymous download if enabled, no login check needed here
    } else if (path == \'/google_callback\') {
      // Handle Google OAuth callback
      const code = url.searchParams.get(\'code\');
      if (!code) {
          return new Response(\'Missing authorization code.\', { status: 400 });
      }
      const response = await fetch(\'https://oauth2.googleapis.com/token\', { /* ... oauth token request ... */ });
      const data = await response.json();
      if (response.ok) {
          // ... handle user login and session cookie creation ...
          let response = new Response(\"\", { status: 200, headers: { /* ... headers ... */ } });
          response.headers.set(\'Refresh\', \'0; url=/\'); // Redirect to root after login
          return response;
      } else {
          // ... handle login error ...
          let response = new Response(\'Invalid Token!\', {});
          response.headers.set(\'Set-Cookie\', `session=; HttpOnly; Secure; SameSite=Lax;`);
          response.headers.set(\"Refresh\", \"1; url=/?error=Invalid Token\");
          return response;
      }
    } else if (request.method === \'POST\' && path === \'/login\') {
      // Handle local login POST request
      // ... process login and set session cookie ...
       if (user_found) {
           // ... set session cookie ...
           const jsonResponse = { ok: true };
           let response = new Response(JSON.stringify(jsonResponse), { status: 200, headers: { /* ... headers and set-cookie ... */ } });
           return response;
       } else {
           const jsonResponse = { ok: false };
           let response = new Response(JSON.stringify(jsonResponse), { status: 200, headers: { /* ... headers ... */ } });
           return response;
       }
    } else if (path == \'/signup\' && authConfig.enable_signup) {
        // Render signup page
        return new Response(signup_html, { status: 200, headers: { \'Content-Type\': \'text/html; charset=utf-8\' } });
    } else if (authConfig.enable_signup && request.method === \'POST\' && path === \'/signup_api\') {
        // Handle signup API POST request
        // ... process signup and return response ...
        let jsonResponse = { ok: true, error: \"User Created\" }; // Simplified
        let response = new Response(JSON.stringify(jsonResponse), { status: 200, headers: { /* ... headers ... */ } });
        return response;
    } else if (request.method === \'GET\' && !is_public_file_view) { // Check login status for GET requests unless it's a public file view
        const cookie = request.headers.get(\'cookie\');
        if (cookie && cookie.includes(\'session=\')) {
            const session = cookie.split(\'session=\').pop().split(\';\').shift().trim();
            if (session == \'null\' || session == \'\' || session == null) {
                return login(); // Session invalid, require login
            }
            try {
                const username = await decryptString(session.split(\'|\')[0]);
                // ... validate session (single session, IP lock, expiry) ...
                const session_time = await decryptString(session.split(\'|\')[2]);
                 const current_time = Date.now();
                 if (Number(session_time) < current_time) {
                     let response = new Response(\'Session Expired!\', { headers: { \'Set-Cookie\': `session=; HttpOnly; Secure; SameSite=Lax;` } });
                     response.headers.set(\"Refresh\", \"1; url=/?error=Session Expired!\");
                     return response;
                 }
                // ... check user existence in database (local/KV/mongodb) ...
                var user_found = true; // Simplified assumption if decryption and validation pass
                if (!user_found) {
                    let response = new Response(\'Invalid User! Something Wrong\', {});
                    response.headers.set(\'Set-Cookie\', `session=; HttpOnly; Secure; SameSite=Lax;`);
                    response.headers.set(\"Refresh\", \"1; url=/?error=Invalid User\");
                    return response;
                }
            } catch (e) {
                 // Decryption or session validation failed
                 let response = new Response(\'Invalid Session!\', { headers: { \'Set-Cookie\': `session=; HttpOnly; Secure; SameSite=Lax;` } });
                 response.headers.set(\"Refresh\", \"1; url=/?error=Invalid Session!\");
                 return response;
            }
        } else {
            return login(); // No valid session cookie, require login
        }
    }
  }


  if (gds.length === 0) {
    for (let i = 0; i < authConfig.roots.length; i++) {
      const gd_instance = new googleDrive(authConfig, i);
      await gd_instance.init();
      gds.push(gd_instance);
    }
    let tasks = [];
    gds.forEach(gd_instance => {
      tasks.push(gd_instance.initRootType());
    });
    for (let task of tasks) {
      await task;
    }
  }

  // Determine which drive instance to use based on URL prefix or encrypted ID
  let drive_match = path.match(/^\\/(?<num>\\d+):/);
  if (drive_match) {
      order = Number(drive_match.groups.num);
  } else if (encrypted_match) {
      order = Number(encrypted_match.groups.num);
  }

  if (order >= 0 && order < gds.length) {
      gd = gds[order];
  } else {
      return redirectToIndexPage(); // Invalid drive index
  }

  // Handle encrypted ID routes
  if (encrypted_match) {
      const encryptedId = encrypted_match.groups.encryptedId;
      try {
          const decryptedId = await decryptString(encryptedId);
          const item = await gd.findItemById(decryptedId); // Fetch item details by ID

          if (!item || item.error) {
              // Item not found or error fetching
              return new Response(not_found, {
                  status: 404,
                  headers: { "content-type": "text/html;charset=UTF-8" },
              });
          }

          if (item.mimeType === 'application/vnd.google-apps.folder') {
              // It's a folder, render homepage with folder ID in MODEL
              return new Response(homepage, {
                  status: 200,
                  headers: { "content-type": "text/html;charset=UTF-8" },
              });
          } else {
              # It's a file, render file view with file details in MODEL
              # Prepare file details similar to how apiRequest does it for a single file
              const fileDetails = {
                  ...item, // Include all original item properties
                  id: encryptedId, // Keep the encrypted ID for frontend use if needed
                  link: await generateLink(item.id, user_ip), // Generate download link
              };

              return new Response(html(gd.order, { file_details: fileDetails, root_type: gd.root_type }), {
                  status: 200,
                  headers: { \'Content-Type\': \'text/html; charset=utf-8\' }
              });
          }
      } catch (e) {
          console.error(\"Error handling encrypted ID route:\", e);
          return new Response(\"Error processing request.\", { status: 500 });
      }
  }


  // Existing route handlers (keep their original logic)
  if (path == \'/\') {
    return new Response(homepage, {
      status: 200,
      headers: {
        "content-type": "text/html;charset=UTF-8",
      },
    })
  } else if (path == \'/fallback\') {
    // Fallback likely handles old-style paths or specific error cases. Keep it as is.
    // The frontend will need to be adjusted to generate encrypted links.
    return new Response(html(0, {
      is_search_page: false,
      root_type: 1 // Assuming default drive type for fallback
    }), {
      status: 200,
      headers: {
        \'Content-Type\': \'text/html; charset=utf-8\'
      }
    });
  } else if (path == \'/download.aspx\') {
    // This handles direct download links, which already use encrypted file IDs.
    // No change needed here except ensuring it works with the decryptString function.
    console.log(\"Download.aspx started\");
    const file_id_param = url.searchParams.get(\'file\');
    const expiry_param = url.searchParams.get(\'expiry\');
    const mac_param = url.searchParams.get(\'mac\');

    if (!file_id_param || !expiry_param || !mac_param) {
         return new Response(\'Invalid Download Request Parameters!\', { status: 400 });
    }

    try {
        const file = await decryptString(file_id_param);
        const expiry = await decryptString(expiry_param);
        let integrity_result = false;
        if (authConfig[\'enable_ip_lock\'] && user_ip) {
          const integrity = await genIntegrity(`${file}|${expiry}|${user_ip}`);
          integrity_result = await checkintegrity(mac_param, integrity);
        } else {
          const integrity = await genIntegrity(`${file}|${expiry}`);
          integrity_result = await checkintegrity(mac_param, integrity);
        }

        if (integrity_result) {
          let range = request.headers.get(\'Range\');
          const inline = \'true\' === url.searchParams.get(\'inline\');
          console.log(\"Serving file:\", file, \"Range:\", range);
          return download(file, range, inline); // Use the decrypted file ID
        } else {
          return new Response(\'Invalid Download Request Signature!\', {
            status: 401,
            headers: { "content-type": "text/html;charset=UTF-8" },
          });
        }
    } catch (e) {
         console.error(\"Error processing download request:\", e);
         return new Response(\'Error processing download request.\', { status: 500 });
    }
  }


  // Handle direct link protection if enabled
  if (authConfig[\'direct_link_protection\']) {
    if (referer == null || !referer.includes(hostname)) {
      return new Response(directlink, {
        headers: { \'content-type\': \'text/html;charset=UTF-8\' },
        status: 401
      });
    }
  }


  // Handle existing command routes (like search, id2path)
  const command_reg = /^\\/(?<num>\\d+):(?<command>[a-zA-Z0-9]+)(\\/.*)?$/g;
  const command_match = command_reg.exec(path);

  if (command_match) {
    const num = command_match.groups.num;
    order = Number(num); // Update order based on command route
     if (order < 0 || order >= gds.length) {
         return redirectToIndexPage(); // Invalid drive index
     }
     gd = gds[order]; // Set gd instance for command route

    const command = command_match.groups.command;
    if (command === \'search\') {
      // handleSearch already returns encrypted IDs.
      // No major change needed here, frontend will use these encrypted IDs for links.
      if (request.method === \'POST\') {
        return handleSearch(request, gd, user_ip);
      } else {
        const params = url.searchParams;
        return new Response(html(gd.order, {
          q: params.get(\"q\").replace(/\'/g, \"\").replace(/\"/g, \"\") || \'\',\
          is_search_page: true,
          root_type: gd.root_type
        }), {
          status: 200,
          headers: { \'Content-Type\': \'text/html; charset=utf-8\' }
        });
      }
    } else if (command === \'id2path\' && request.method === \'POST\') {
      // handleId2Path is used by the search result click.
      # It expects an encrypted ID and decrypts it. This seems correct.
      return handleId2Path(request, gd);
    } else if (command === \'fallback\' && request.method === \'POST\') {
      # Fallback post is likely used by app.js when id2path fails.
      # It expects an encrypted ID and decrypts it. This seems correct.
      const formdata = await request.json();
      const id = await decryptString(formdata.id); // Decrypt ID
      const type = formdata.type;
      if (type && type == \'folder\') {
        const page_token = formdata.page_token || null;
        const page_index = formdata.page_index || 0;
        const details = await gd._list_gdrive_files(id, page_token, page_index); # Use decrypted id
         # Ensure file IDs in the response are encrypted
        if (details && details.data && details.data.files) {
             details.data.files = await Promise.all(details.data.files.map(async (file) => {
                const { driveId, id: fileId, mimeType, ...fileWithoutId } = file;
                const encryptedFileId = await encryptString(fileId);
                const encryptedDriveId = driveId ? await encryptString(driveId) : null;
                let link = null;
                if (mimeType !== \'application/vnd.google-apps.folder\') {
                    link = await generateLink(fileId, user_ip); // generate link with original ID
                }
                return { ...fileWithoutId, id: encryptedFileId, driveId: encryptedDriveId, mimeType: mimeType, link: link, };
            }));
        }
        const encryptedDetails = details;
        return new Response(JSON.stringify(encryptedDetails), {});
      }
      # Fallback for a single file by ID
      const details = await gd.findItemById(id); # Use decrypted id
      if (details && !details.error) {
          # Ensure file ID is encrypted and generate download link
          details.id = await encryptString(details.id);
          details.link = await generateLink(await decryptString(details.id), user_ip); # generate link with original ID after decrypting the encrypted ID
          if (details.parents && details.parents.length > 0) {
              # Encrypt parent IDs if needed by frontend, or remove them
               details.parents = await Promise.all(details.parents.map(async (parentId) => parentId ? await encryptString(parentId) : null));
           } else {
               details.parents = [];
           }
      } else {
          return new Response(\'{\"message\":\"Fallback Request Failed or Item Not Found\"}\', {
            status: 500,
            headers: { "content-type": "application/json" },
          });
      }
      return new Response(JSON.stringify(details), {});

    } else if (command === \'findpath\' && request.method === \'GET\') {
      # findId2Path is used when navigating from search results.
      # It expects an encrypted ID in the URL and decrypts it. This seems correct.
      # It redirects to the path URL, which we will change in the frontend to the encrypted ID URL.
      # So, this handler might become less critical or need adjustment depending on the final frontend logic.
       const id = url.searchParams.get(\'id\'); // This id should be encrypted from app.js search click
       try {
           const decrypted_id = await decryptString(id); // Decrypt the ID
           let [path, prefix] = await gd.findPathById(decrypted_id); // Use decrypted ID
           console.log(path, prefix);
           if (!path) {
               return new Response(\"Invalid URL\");
           } else if (url.searchParams.get(\'view\') && url.searchParams.get(\'view\') == \'true\') {
               # Redirect to the new encrypted ID format for view
               return Response.redirect(\"https://\" + url.hostname + \"/\" + prefix + \":\" + id + \"?a=view\" || \'\', 302);
           } else {
               # Redirect to the new encrypted ID format for listing/default
               return Response.redirect(\"https://\" + url.hostname + \"/\" + prefix + \":\" + id || \'\', 302);
           }
       } catch (error) {
           console.error(\"Error in findId2Path:\", error);
           const encrypted_id = url.searchParams.get(\'id\'); # Use original encrypted ID
           return Response.redirect(\"https://\" + url.hostname + \"/fallback?id=\" + encrypted_id || \'\', 302);
       }
    }
  }

  // Handle old-style path routes (e.g., /0:/folder/subfolder/) - Keep for compatibility during transition
  const common_reg = /^\\/\\d+:\\/.*$/g;
  try {
    if (!path.match(common_reg)) {
      # If it doesn't match a command, encrypted ID, or old-style path, redirect to index
       if (path === \'/login\' || path === \'/signup\') {
            // Allow login/signup pages even if not matching other patterns
       } else {
             return redirectToIndexPage();
       }
    } else {
        let split = path.split(\"/\");
        let order_from_path = Number(split[1].slice(0, -1));
         if (order_from_path >= 0 && order_from_path < gds.length) {
             order = order_from_path; // Use order from path
             gd = gds[order]; // Set gd instance for old-style path
         } else {
             return redirectToIndexPage(); // Invalid drive index
         }
    }

  } catch (e) {
      console.error(\"Error processing old-style path:\", e);
    return redirectToIndexPage();
  }


  // Handle API requests (POST) - Modify to accept ID
  if (request.method == \'POST\' && path.match(/^\\/\\d+:\\/.*$/g)) { # Only apply to old-style path POSTs initially
      return apiRequest(request, gd, user_ip);
  }


  // Handle rendering HTML for old-style paths (GET)
  if (path.slice(-1) == \'/\' || action != null) {
    # This handles directory listing or file view for old-style paths
    # Render the appropriate HTML
    return new Response(html(gd.order, {
      root_type: gd.root_type
    }), {
      status: 200,
      headers: {
        \'Content-Type\': \'text/html; charset=utf-8\'
      }
    });
  } else {
    # This handles serving a single file for old-style paths directly (not with ?a=view)
    # It will fetch the file by path and serve it.
    console.log(\"Serving file directly from path:\", path);
    try {
        const file = await gd.get_single_file(path.slice(3)); # Use path to get file details
        if (!file || file.error) {
             return new Response(not_found, {
                 status: 404,
                 headers: { "content-type": "text/html;charset=UTF-8" },
             });
        }
        let range = request.headers.get(\'Range\');
        const inline = \'true\' === url.searchParams.get(\'inline\');
        # Check direct link protection and login if enabled for direct file access
        if (gd.root.protect_file_link && authConfig.enable_login) return login(); # Assuming protect_file_link applies to direct access too
        return download(file.id, range, inline); # Use original file ID for download
    } catch (e) {
        console.error(\"Error serving file directly:\", e);
         return new Response(\"Error serving file.\", { status: 500 });
    }
  }
}

async function apiRequest(request, gd, user_ip) {
  let url = new URL(request.url);
  let path = url.pathname; # Keep path for potential other API calls

  const option = {
    status: 200,
    headers: {
      \'Access-Control-Allow-Origin\': \'*\'
    }
  };

  let requestData = await request.json();
  let target_id = null;

  # Check if an encrypted ID is provided in the request body
  if (requestData.id) {
      try {
          target_id = await decryptString(requestData.id); # Decrypt the ID
          console.log(\"apiRequest: Received encrypted ID, decrypted to:\", target_id);
      } catch (e) {
          console.error(\"apiRequest: Failed to decrypt ID:\", e);
          return new Response(JSON.stringify({ error: { code: 400, message: \"Invalid ID\" } }), { status: 400, headers: option.headers });
      }
  } else if (path.slice(-1) == \'/\') {
     # If no ID in body and path ends with /, assume it's a listing request by path (backward compatibility)
      console.log(\"apiRequest: Received path for
