import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";

// ---------------------------------------------
// 1. CONFIGURE THESE VALUES
// ---------------------------------------------
const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

// ---------------------------------------------
// 2. INIT CLIENT
// ---------------------------------------------
const supabase = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);

// ---------------------------------------------
// 3. HELPER: detect if a password is already hashed
// ---------------------------------------------
function isHashed(password) {
  return typeof password === "string" && password.startsWith("$2");
}

// ---------------------------------------------
// 4. MAIN MIGRATION
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
