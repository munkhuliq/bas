// ============================================================
//  Edge Function: admin
//  إدارة حسابات الموظفين (إنشاء/حذف/تعديل بيانات الدخول) بصلاحية الخادم.
//
//  النشر (عبر اللوحة):
//   Edge Functions → Create a new function → الاسم: admin → الصق هذا الملف → Deploy
//  المتغيرات السرية: SUPABASE_URL و SUPABASE_SERVICE_ROLE_KEY مهيّأة تلقائياً.
// ============================================================
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const EMAIL_DOMAIN = "@basma.local";
const USER_RE = /^[a-z0-9_]{3,20}$/;

// عيّن ALLOWED_ORIGIN في متغيرات البيئة بنطاقك الفعلي (مثال: https://basma.example.com)
// إن لم يُعيَّن يُسمح بأي أصل — مقبول مؤقتاً لأن كل طلب يتحقق من JWT المدير
const ALLOWED_ORIGIN = Deno.env.get("ALLOWED_ORIGIN") || "*";
const cors = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const admin = createClient(SUPABASE_URL, SERVICE_ROLE, { auth: { persistSession: false } });
    const body = await req.json();
    const action = body.action;

    // ---------- كل العمليات تتطلب أن يكون المتصل مديراً ----------
    const token = (req.headers.get("Authorization") || "").replace("Bearer ", "");
    if (!token) return json({ error: "unauthorized" }, 401);
    const { data: { user: caller }, error: cerr } = await admin.auth.getUser(token);
    if (cerr || !caller) return json({ error: "unauthorized" }, 401);
    const { data: callerProfile } = await admin.from("profiles").select("role").eq("id", caller.id).single();
    if (!callerProfile || callerProfile.role !== "admin") return json({ error: "forbidden" }, 403);

    // ---------- إنشاء موظف ----------
    if (action === "create-employee") {
      const username = String(body.username || "").toLowerCase();
      const password = String(body.password || "");
      const p = body.profile || {};
      if (!USER_RE.test(username)) return json({ error: "invalid username" }, 400);
      if (password.length < 6) return json({ error: "weak password" }, 400);

      const { data: created, error } = await admin.auth.admin.createUser({
        email: username + EMAIL_DOMAIN, password, email_confirm: true,
        user_metadata: { username, name: p.name || username },
        app_metadata: { created_by: "admin" },   // علامة تسمح بتجاوز مانع التسجيل العام
      });
      if (error || !created?.user) return json({ error: error?.message || "create failed" }, 400);

      const { error: pe } = await admin.from("profiles").insert({
        id: created.user.id, username, name: p.name || username, role: "employee",
        rate: p.rate ?? null, pay_type: p.pay_type || "hourly",
        monthly_salary: p.monthly_salary ?? null, late_deduct_per_hour: p.late_deduct_per_hour ?? null,
        daily_hours: p.daily_hours ?? 8,
      });
      if (pe) { await admin.auth.admin.deleteUser(created.user.id); return json({ error: pe.message }, 400); }
      return json({ ok: true });
    }

    // ---------- حذف موظف (مع كل سجلاته) ----------
    if (action === "delete-employee") {
      const username = String(body.username || "").toLowerCase();
      const { data: prof } = await admin.from("profiles").select("id,role").eq("username", username).single();
      if (!prof) return json({ error: "not found" }, 404);
      if (prof.role === "admin") return json({ error: "cannot delete admin" }, 400);
      await admin.from("attendance").delete().eq("username", username);
      await admin.from("deductions").delete().eq("username", username);
      await admin.from("bonuses").delete().eq("username", username);
      await admin.from("leaves").delete().eq("username", username);
      const { error } = await admin.auth.admin.deleteUser(prof.id); // يحذف profile تلقائياً (cascade)
      if (error) return json({ error: error.message }, 400);
      return json({ ok: true });
    }

    // ---------- تغيير اسم المستخدم و/أو كلمة المرور ----------
    if (action === "set-credentials") {
      const username = String(body.username || "").toLowerCase();
      const newUsername = body.newUsername ? String(body.newUsername).toLowerCase() : null;
      const newPassword = body.newPassword ? String(body.newPassword) : null;
      if (newUsername && !USER_RE.test(newUsername)) return json({ error: "invalid username" }, 400);
      if (newPassword && newPassword.length < 6) return json({ error: "weak password" }, 400);

      const { data: prof } = await admin.from("profiles").select("id").eq("username", username).single();
      if (!prof) return json({ error: "not found" }, 404);

      const upd: Record<string, string> = {};
      if (newPassword) upd.password = newPassword;
      if (newUsername) {
        const { data: exists } = await admin.from("profiles").select("id").eq("username", newUsername).maybeSingle();
        if (exists) return json({ error: "username exists" }, 400);
        upd.email = newUsername + EMAIL_DOMAIN;
      }
      if (Object.keys(upd).length) {
        const { error } = await admin.auth.admin.updateUserById(prof.id, upd);
        if (error) return json({ error: error.message }, 400);
      }
      if (newUsername) {
        const { error: pe } = await admin.from("profiles").update({ username: newUsername }).eq("id", prof.id);
        if (pe) return json({ error: pe.message }, 400);
      }
      return json({ ok: true });
    }

    return json({ error: "unknown action" }, 400);
  } catch (e) {
    return json({ error: String((e as Error)?.message || e) }, 500);
  }
});
