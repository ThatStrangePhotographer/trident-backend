import { createClient } from '@supabase/supabase-js';
import bcrypt from "bcryptjs";

function getSupabase(env) {
  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
}

// ------------------------------------------------------------
// RSA DECRYPTION
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
// MAIN WORKER
// ------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");
    const allowed = /^https:\/\/([a-z0-9-]+\.)*tridenthq\.team$/i;

    // CORS preflight
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
    // LOGIN
    // ============================================================
    if (url.pathname === "/api/login" && request.method === "POST") {
      const { username, password: encryptedPassword } = await request.json();

      if (!username || !encryptedPassword) {
        return wrapCors(new Response("Missing username or password", { status: 400 }), origin, allowed);
      }

      const { data: user, error } = await supabase
        .from("members")
        .select("id, username, password, role")
        .eq("username", username.toLowerCase())
        .maybeSingle();

      if (error || !user) {
        return wrapCors(new Response("Invalid username or password", { status: 401 }), origin, allowed);
      }

      let plaintext;
      try {
        plaintext = await decryptPassword(env, encryptedPassword);
      } catch {
        return wrapCors(new Response("Invalid username or password", { status: 401 }), origin, allowed);
      }

      const valid = await bcrypt.compare(plaintext, user.password);
      if (!valid) {
        return wrapCors(new Response("Invalid username or password", { status: 401 }), origin, allowed);
      }

      const session = {
        id: user.id,
        username: user.username,
        role: user.role,
        created_at: Date.now()
      };

      return wrapCors(Response.json(session), origin, allowed);
    }

    // ============================================================
    // GROUPS (GET)
    // ============================================================
    if (/^\/api\/groups\/?$/.test(url.pathname) && request.method === "GET") {
      const { data, error } = await supabase
        .from("groups")
        .select("*")
        .order("name", { ascending: true });

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);
      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBERS (GET)
    // ============================================================
    if (/^\/api\/members\/?$/.test(url.pathname) && request.method === "GET") {
      const username = url.searchParams.get("username");
      const all = url.searchParams.get("all");

      let query = supabase.from("members").select("password, role, is_active, watch, rank, display_name, username, id, password_encrypted");

      if (username) query = query.eq("username", username.toLowerCase());
      if (!all) query = query.eq("is_active", true);

      const { data, error } = await query;
      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBERS (CREATE)
    // ============================================================
    if (/^\/api\/members\/?$/.test(url.pathname) && request.method === "POST") {
      const body = await request.json();

      const plaintext = await decryptPassword(env, body.password);
      const hashedPassword = await bcrypt.hash(plaintext, 10);

      const row = {
        username: body.username?.toLowerCase(),
        display_name: body.display_name,
        role: body.role,
        rank: body.rank ?? null,
        watch: body.watch ?? null,
        is_active: body.active ?? true,
        password: hashedPassword,
        password_encrypted: body.password,
        password_plaintext: plaintext
      };

      const { data, error } = await supabase
        .from("members")
        .insert(row)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBERS (UPDATE)
    // ============================================================
    const memberMatch = url.pathname.match(/^\/api\/members\/(.+)$/);
    if (memberMatch && request.method === "PATCH") {
      const id = memberMatch[1];
      const body = await request.json();

      const updateData = {
        username: body.username?.toLowerCase(),
        display_name: body.display_name,
        role: body.role,
        rank: body.rank ?? null,
        watch: body.watch ?? null
      };

      if (body.active !== undefined) {
        updateData.is_active = body.active;
      }

      if (body.password) {
        const plaintext = await decryptPassword(env, body.password);
        updateData.password = await bcrypt.hash(plaintext, 10);
        updateData.password_encrypted = body.password;
        updateData.password_plaintext = plaintext;
      }

      const { data, error } = await supabase
        .from("members")
        .update(updateData)
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBERS (DELETE)
    // ============================================================
    const memberDeleteMatch = url.pathname.match(/^\/api\/members\/(.+)$/);
    if (memberDeleteMatch && request.method === "DELETE") {
      const id = memberDeleteMatch[1];

      const { data, error } = await supabase
        .from("members")
        .delete()
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json({ success: true, deleted: data }), origin, allowed);
    }

    // ============================================================
    // MEMBER ROLES (GET)
    // ============================================================
    if (/^\/api\/member-roles\/?$/.test(url.pathname) && request.method === "GET") {
      const { data, error } = await supabase
        .from("member_roles")
        .select("*")
        .order("member_name", { ascending: true });

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBER ROLES (CREATE)
    // ============================================================
    if (/^\/api\/member-roles\/?$/.test(url.pathname) && request.method === "POST") {
      const body = await request.json();

      const { data, error } = await supabase
        .from("member_roles")
        .insert(body)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // MEMBER ROLES (UPDATE / DELETE)
    // ============================================================
    const roleMatch = url.pathname.match(/^\/api\/member-roles\/(.+)$/);

    if (roleMatch && request.method === "PATCH") {
      const id = roleMatch[1];
      const body = await request.json();

      const { data, error } = await supabase
        .from("member_roles")
        .update(body)
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    if (roleMatch && request.method === "DELETE") {
      const id = roleMatch[1];

      const { data, error } = await supabase
        .from("member_roles")
        .delete()
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json({ success: true, deleted: data }), origin, allowed);
    }

    // ============================================================
    // DRILL REFERENCES (GET)
    // ============================================================
    if (/^\/api\/drill-references\/?$/.test(url.pathname) && request.method === "GET") {
      const category = url.searchParams.get("category");

      let query = supabase.from("drillreference").select("*");
      if (category) query = query.eq("category", category);

      const { data, error } = await query.order("difficulty", { ascending: true });
      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // DRILL REFERENCES (CREATE)
    // ============================================================
    if (/^\/api\/drill-references\/?$/.test(url.pathname) && request.method === "POST") {
      const body = await request.json();

      const { data, error } = await supabase
        .from("drillreference")
        .insert(body)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // DRILL REFERENCES (UPDATE / DELETE)
    // ============================================================
    const drillMatch = url.pathname.match(/^\/api\/drill-references\/(.+)$/);

    if (drillMatch && request.method === "PATCH") {
      const id = drillMatch[1];
      const body = await request.json();

      const { data, error } = await supabase
        .from("drillreference")
        .update(body)
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    if (drillMatch && request.method === "DELETE") {
      const id = drillMatch[1];

      const { data, error } = await supabase
        .from("drillreference")
        .delete()
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json({ success: true, deleted: data }), origin, allowed);
    }

    // ============================================================
    // SESSIONS (GET)
    // ============================================================
    if (/^\/api\/sessions\/?$/.test(url.pathname) && request.method === "GET") {
      const all = url.searchParams.get("all");

      let query = supabase.from("session").select("*");

      if (!all) {
        const today = new Date().toISOString().split("T")[0];
        query = query.gte("date", today);
      }

      const { data, error } = await query.order("date", { ascending: false });
      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // SESSIONS (CREATE)
    // ============================================================
    if (/^\/api\/sessions\/?$/.test(url.pathname) && request.method === "POST") {
      const body = await request.json();

      const { data, error } = await supabase
        .from("session")
        .insert(body)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // SESSIONS (UPDATE / DELETE)
    // ============================================================
    const sessionMatch = url.pathname.match(/^\/api\/sessions\/(.+)$/);

    if (sessionMatch && request.method === "PATCH") {
      const id = sessionMatch[1];
      const body = await request.json();

      const { data, error } = await supabase
        .from("session")
        .update(body)
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    if (sessionMatch && request.method === "DELETE") {
      const id = sessionMatch[1];

      const { data, error } = await supabase
        .from("session")
        .delete()
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json({ success: true, deleted: data }), origin, allowed);
    }

    // ============================================================
    // ATTENDANCE (GET)
    // ============================================================
    if (/^\/api\/attendance\/?$/.test(url.pathname) && request.method === "GET") {
      const session_id = url.searchParams.get("session_id");

      let query = supabase.from("attendance").select("*");
      if (session_id) query = query.eq("session_id", session_id);

      const { data, error } = await query.order("created_date", { ascending: false });
      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // ATTENDANCE (CREATE)
    // ============================================================
    if (/^\/api\/attendance\/?$/.test(url.pathname) && request.method === "POST") {
      const body = await request.json();

      const { data, error } = await supabase
        .from("attendance")
        .insert(body)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // ATTENDANCE (UPDATE)
    // ============================================================
    const attendanceMatch = url.pathname.match(/^\/api\/attendance\/(.+)$/);
    if (attendanceMatch && request.method === "PATCH") {
      const id = attendanceMatch[1];
      const body = await request.json();

      const { data, error } = await supabase
        .from("attendance")
        .update(body)
        .eq("id", id)
        .select()
        .single();

      if (error) return wrapCors(new Response(error.message, { status: 500 }), origin, allowed);

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // FALLBACK
    // ============================================================
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
