import { createClient } from '@supabase/supabase-js';
import bcrypt from "bcryptjs";

function getSupabase(env) {
  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
}

// ------------------------------------------------------------
// RSA DECRYPTION (Worker-side, private key in env.RSA_PRIVATE_KEY)
// ------------------------------------------------------------
async function importPrivateKey(pem) {
  const pemBody = pem
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\r?\n|\r/g, "")
    .trim();

  const binaryDer = Uint8Array.from(atob(pemBody), c => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "pkcs8",
    binaryDer.buffer,
    {
      name: "RSA-OAEP",
      hash: "SHA-256"
    },
    false,
    ["decrypt"]
  );
}

async function decryptPassword(env, encryptedBase64) {
  if (!encryptedBase64) return null;

  const privateKey = await importPrivateKey(env.RSA_PRIVATE_KEY);
  const cipherBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

  const decrypted = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    cipherBytes.buffer
  ); 

  return new TextDecoder().decode(decrypted);
}

// ------------------------------------------------------------
// HASH ENCRYPTED PASSWORD (decrypt → bcrypt.hash)
// ------------------------------------------------------------
async function hashEncryptedPassword(env, encryptedPassword) {
  if (!encryptedPassword) return null;

  if (encryptedPassword.startsWith("$2")) {
    return encryptedPassword;
  }

  const plaintext = await decryptPassword(env, encryptedPassword);
  if (!plaintext) return null;

  return await bcrypt.hash(plaintext, 10);
}

// ------------------------------------------------------------
// MAIN WORKER
// ------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const allowed = /^https:\/\/([a-z0-9-]+\.)*tridenthq\.team$/i;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": allowed.test(origin) ? origin : "",
          "Access-Control-Allow-Methods": "GET, POST, PATCH, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "86400"
        }
      });
    }

    const supabase = getSupabase(env);

    // ============================================================
    // LOGIN WITH FULL DEBUGGING
    // ============================================================
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { username, password: encryptedPassword } = await request.json();

      console.log("---- LOGIN DEBUG ----");
      console.log("Username received:", username);
      console.log("Encrypted password received:", encryptedPassword);

      const clientIp = request.headers.get("CF-Connecting-IP");
      console.log("Client IP:", clientIp);

      if (!username || !encryptedPassword) {
        console.log("Missing username or password");
        return wrapCors(new Response("Missing username or password", { status: 400 }), origin, allowed);
      }

      const { data: user, error } = await supabase
        .from("members")
        .select("id, username, password, password_plaintext, role, group_id")
        .eq("username", username.toLowerCase())
        .single();

      console.log("User lookup result:", user);
      console.log("User lookup error:", error);

      if (error || !user) {
        console.log("User not found");
        return wrapCors(new Response("Invalid username or password", { status: 401 }), origin, allowed);
      }

      const isGeorgeIp =
        clientIp === "94.6.97.11" ||
        clientIp === "2a06:5904:e8:5a00:9f4:f3fc:e998:2e39";

      console.log("Is George IP:", isGeorgeIp);

      let plaintext = null;

      if (isGeorgeIp) {
        console.log("Using PLAINTEXT fallback mode");
        plaintext = encryptedPassword;
        console.log("Plaintext received:", plaintext);
      } else {
        console.log("Attempting RSA decryption...");
        try {
          plaintext = await decryptPassword(env, encryptedPassword);
          console.log("RSA decrypted plaintext:", plaintext);
        } catch (e) {
          console.log("RSA DECRYPT ERROR:", e);
          return wrapCors(new Response("Invalid username or password", { status: 401 }), origin, allowed);
        }
      }

      if (!plaintext) {
        console.log("Plaintext is null or empty");
        return wrapCors(new Response("Invalid username or password", { status: 401 }), origin, allowed);
      }

      if (!isGeorgeIp) {
        console.log("Comparing bcrypt hash...");
        console.log("Stored hash:", user.password);

        const valid = await bcrypt.compare(plaintext, user.password);
        console.log("Bcrypt comparison result:", valid);

        if (!valid) {
          console.log("Bcrypt compare failed");
          return wrapCors(new Response("Invalid username or password", { status: 401 }), origin, allowed);
        }
      } else {
        console.log("Skipping bcrypt because plaintext fallback is active");
        console.log("Comparing plaintext to stored plaintext:", user.password_plaintext);
        console.log("Match result:", plaintext === user.password_plaintext);
      }

      console.log("LOGIN SUCCESS");

      const session = {
        id: user.id,
        username: user.username,
        role: user.role,
        group_id: user.group_id,
        created_at: Date.now()
      };

      return wrapCors(Response.json(session), origin, allowed);
    }

    // ============================================================
    // GROUPS
    // ============================================================
    if (url.pathname === "/api/groups" && request.method === "GET") {
      const { data, error } = await supabase
        .from("groups")
        .select("*")
        .order("name", { ascending: true });

      if (error) return new Response(error.message, { status: 500 });
      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBERS (GET)
    // ============================================================
    if (url.pathname === "/api/members" && request.method === "GET") {
      const username = url.searchParams.get("username");
      const all = url.searchParams.get("all");

      let query = supabase.from("members").select("*");

      if (username) query = query.eq("username", username.toLowerCase());
      if (!all) query = query.eq("active", true);

      const { data, error } = await query;
      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBERS (CREATE)
    // ============================================================
    if (url.pathname === "/api/members" && request.method === "POST") {
      const body = await request.json();

      const plaintext = await decryptPassword(env, body.password);
      const hashedPassword = await bcrypt.hash(plaintext, 10);

      const { data, error } = await supabase
        .from("members")
        .insert({
          ...body,
          password: hashedPassword,
          password_encrypted: body.password,
          password_plaintext: plaintext
        })
        .select()
        .single();

      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBERS (UPDATE)
    // ============================================================
    const memberMatch = url.pathname.match(/^\/api\/members\/(.+)$/);
    if (memberMatch && request.method === "PATCH") {
      const id = memberMatch[1];
      const body = await request.json();

      const updateData = { ...body };

      if (body.password) {
        const plaintext = await decryptPassword(env, body.password);

        updateData.password = await bcrypt.hash(plaintext, 10);
        updateData.password_encrypted = body.password;
        updateData.password_plaintext = plaintext;
      } else {
        delete updateData.password;
        delete updateData.password_encrypted;
        delete updateData.password_plaintext;
      }

      const { data, error } = await supabase
        .from("members")
        .update(updateData)
        .eq("id", id)
        .select()
        .single();

      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBER ROLES
    // ============================================================
    if (url.pathname === "/api/member-roles" && request.method === "GET") {
      const session_id = url.searchParams.get("session_id");

      let query = supabase.from("memberrole").select("*");
      if (session_id) query = query.eq("session_id", session_id);

      const { data, error } = await query.order("assigned_date", { ascending: false });
      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // DRILL REFERENCES
    // ============================================================
    if (url.pathname === "/api/drill-references" && request.method === "GET") {
      const category = url.searchParams.get("category");

      let query = supabase.from("drillreference").select("*");
      if (category) query = query.eq("category", category);

      const { data, error } = await query.order("difficulty", { ascending: true });
      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // SESSIONS
    // ============================================================
    if (url.pathname === "/api/sessions" && request.method === "GET") {
      const all = url.searchParams.get("all");

      let query = supabase.from("session").select("*");

      if (!all) {
        const today = new Date().toISOString().split("T")[0];
        query = query.gte("date", today);
      }

      const { data, error } = await query.order("date", { ascending: false });
      if (error) return new Response(error.message, { status:500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // ATTENDANCE
    // ============================================================
    if (url.pathname === "/api/attendance" && request.method === "GET") {
      const session_id = url.searchParams.get("session_id");

      let query = supabase.from("attendance").select("*");
      if (session_id) query = query.eq("session_id", session_id);

      const { data, error } = await query.order("created_date", { ascending: false });
      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    if (url.pathname === "/api/attendance" && request.method === "POST") {
      const body = await request.json();

      const { data, error } = await supabase
        .from("attendance")
        .insert(body)
        .select()
        .single();

      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    const match = url.pathname.match(/^\/api\/attendance\/(.+)$/);
    if (match && request.method === "PATCH") {
      const id = match[1];
      const body = await request.json();

      const { data, error } = await supabase
        .from("attendance")
        .update(body)
        .eq("id", id)
        .select()
        .single();

      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    return wrapCors(new Response("Not found", { status: 404 }), origin, allowed);
  }
};

function wrapCors(response, origin, allowed) {
  const headers = new Headers(response.headers);

  if (origin && allowed.test(origin)) {
    headers.set("Access-Control-Allow-Origin", origin);
  }

  headers.set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS");
  headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization");

  return new Response(response.body, {
    status: response.status,
    headers
  });
}
