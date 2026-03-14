import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";

// Load .env file
dotenv.config();

// ---------------------------------------------
// 1. Use the same pattern as your Worker
// ---------------------------------------------
function getSupabase() {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url) throw new Error("Missing SUPABASE_URL in .env");
  if (!key) throw new Error("Missing SUPABASE_SERVICE_ROLE_KEY in .env");

  return createClient(url, key);
}

const supabase = getSupabase();

// ---------------------------------------------
// 2. Helper: detect if password is already hashed
// ---------------------------------------------
function isHashed(password) {
  return typeof password === "string" && password.startsWith("$2");
}

// ---------------------------------------------
// 3. Migration logic
// ---------------------------------------------
async function migrate() {
  console.log("Fetching members...");

  const { data: members, error } = await supabase
    .from("members")
    .select("id, username, password");

  if (error) {
    console.error("Failed to fetch members:", error);
    return;
  }

  console.log(`Found ${members.length} members`);
  console.log("Starting migration...\n");

  for (const member of members) {
    const { id, username, password } = member;

    if (!password) {
      console.log(`Skipping ${username}: no password set`);
      continue;
    }

    if (isHashed(password)) {
      console.log(`Skipping ${username}: already hashed`);
      continue;
    }

    // Hash plaintext password
    const hashed = await bcrypt.hash(password, 10);

    const { error: updateError } = await supabase
      .from("members")
      .update({ password: hashed })
      .eq("id", id);

    if (updateError) {
      console.error(`❌ Failed to update ${username}:`, updateError);
    } else {
      console.log(`✔ Updated ${username}`);
    }
  }

  console.log("\nMigration complete!");
}

migrate();
