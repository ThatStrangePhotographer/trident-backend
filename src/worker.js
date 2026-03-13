import { createClient } from '@supabase/supabase-js';

function getSupabase(env) {
  return createClient(
    env.SUPABASE_URL,
    env.SUPABASE_SERVICE_ROLE_KEY
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const supabase = getSupabase(env);

    // ----------------------------------------------------
    // GET /api/members
    // ----------------------------------------------------
    if (url.pathname === "/api/members" && request.method === "GET") {
      const username = url.searchParams.get("username");

      let query = supabase.from("members").select("*");
      if (username) query = query.eq("username", username.toLowerCase());

      const { data, error } = await query;
      if (error) return new Response(error.message, { status: 500 });
      return Response.json(data);
    }

    // ----------------------------------------------------
    // GET /api/member-roles
    // ----------------------------------------------------
    if (url.pathname === "/api/member-roles" && request.method === "GET") {
      const session_id = url.searchParams.get("session_id");

      let query = supabase.from("memberrole").select("*");
      if (session_id) query = query.eq("session_id", session_id);

      const { data, error } = await query.order("assigned_date", { ascending: false });
      if (error) return new Response(error.message, { status: 500 });
      return Response.json(data);
    }

    // ----------------------------------------------------
    // GET /api/drill-references
    // ----------------------------------------------------
    if (url.pathname === "/api/drill-references" && request.method === "GET") {
      const category = url.searchParams.get("category");

      let query = supabase.from("drillreference").select("*");
      if (category) query = query.eq("category", category);

      const { data, error } = await query.order("difficulty", { ascending: true });
      if (error) return new Response(error.message, { status: 500 });
      return Response.json(data);
    }

    // ----------------------------------------------------
    // GET /api/sessions
    // ----------------------------------------------------
    if (url.pathname === "/api/sessions" && request.method === "GET") {
      const { data, error } = await supabase
        .from("session")
        .select("*")
        .order("date", { ascending: false });

      if (error) return new Response(error.message, { status: 500 });
      return Response.json(data);
    }

    // ----------------------------------------------------
    // GET /api/attendance
    // ----------------------------------------------------
    if (url.pathname === "/api/attendance" && request.method === "GET") {
      const session_id = url.searchParams.get("session_id");

      let query = supabase.from("attendance").select("*");
      if (session_id) query = query.eq("session_id", session_id);

      const { data, error } = await query.order("created_date", { ascending: false });
      if (error) return new Response(error.message, { status: 500 });
      return Response.json(data);
    }

    // ----------------------------------------------------
    // POST /api/attendance
    // ----------------------------------------------------
    if (url.pathname === "/api/attendance" && request.method === "POST") {
      const body = await request.json();

      const { data, error } = await supabase
        .from("attendance")
        .insert(body)
        .select()
        .single();

      if (error) return new Response(error.message, { status: 500 });
      return Response.json(data);
    }

    // ----------------------------------------------------
    // PATCH /api/attendance/:id
    // ----------------------------------------------------
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
      return Response.json(data);
    }

    // ----------------------------------------------------
    // FALLBACK
    // ----------------------------------------------------
    return new Response("Not found", { status: 404 });
  }
};
