import { createClient } from '@supabase/supabase-js';

function getSupabase(env) {
  return createClient(env.SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");

    // Allow root + any subdomain of tridenthq.team
    const allowed = /^https:\/\/([a-z0-9-]+\.)*tridenthq\.team$/i;

    // -----------------------------
    // Handle CORS preflight
    // -----------------------------
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
    // MEMBERS
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
      const all = url.searchParams.get("all");

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
        // Default: only future or recent sessions
        const today = new Date().toISOString().split("T")[0];
        query = query.gte("date", today);
      }

      const { data, error } = await query.order("date", { ascending: false });
      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    // ============================================================
    // ATTENDANCE
    // ============================================================
    if (url.pathname === "/api/attendance" && request.method === "GET") {
      const session_id = url.searchParams.get("session_id");
      const all = url.searchParams.get("all");

      let query = supabase.from("attendance").select("*");

      if (session_id) query = query.eq("session_id", session_id);

      const { data, error } = await query.order("created_date", { ascending: false });
      if (error) return new Response(error.message, { status: 500 });

      return wrapCors(Response.json(data), origin, allowed);
    }

    // POST /api/attendance
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

    // PATCH /api/attendance/:id
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

    // ============================================================
    // FALLBACK
    // ============================================================
    return wrapCors(new Response("Not found", { status: 404 }), origin, allowed);
  }
};

// Helper to attach CORS headers
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
