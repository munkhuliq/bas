-- ============================================================
--  إعداد قاعدة بيانات Supabase الآمنة لتطبيق "بصمة الحضور"
--  ينقل المصادقة إلى Supabase Auth ويُفعّل حماية الصفوف (RLS).
--  نفّذه في: Supabase Dashboard → SQL Editor → New query → Run
--
--  ⚠️ هذا السكربت يبدأ من قاعدة نظيفة ويحذف الجداول القديمة وبياناتها.
--     إن كان لديك بيانات فعلية يجب الحفاظ عليها، تواصل قبل التشغيل.
-- ============================================================

-- (0) حذف القديم (بداية نظيفة)
drop table if exists public.attendance cascade;
drop table if exists public.deductions cascade;
drop table if exists public.leaves      cascade;
drop table if exists public.settings    cascade;
drop table if exists public.profiles    cascade;

-- ============================================================
-- (1) الجداول
-- ============================================================

-- ملفات المستخدمين: مرتبطة بحساب المصادقة (auth.users) عبر id
create table public.profiles (
  id                   uuid primary key references auth.users(id) on delete cascade,
  username             text unique not null,
  name                 text not null,
  role                 text not null default 'employee' check (role in ('admin','employee')),
  rate                 numeric,
  pay_type             text default 'hourly',
  monthly_salary       numeric,
  late_deduct_per_hour numeric,
  daily_hours          numeric default 8,
  work_days            text   default '0,1,2,3,4,6',
  created_at           timestamptz default now()
);

create table public.attendance (
  id         bigint generated always as identity primary key,
  username   text not null,
  work_date  date not null,
  month      text not null,
  punch_in   timestamptz not null,
  punch_out  timestamptz,
  in_lat     double precision,
  in_lng     double precision,
  out_lat    double precision,
  out_lng    double precision,
  manual     boolean default false,
  created_at timestamptz default now()
);

create table public.settings (
  id           int primary key default 1 check (id = 1),
  geo_lat      double precision,
  geo_lng      double precision,
  geo_rad      int,
  default_rate numeric default 20000,
  app_name     text default 'بصمة الحضور',
  app_logo     text default '📍'
);

create table public.deductions (
  id         bigint generated always as identity primary key,
  username   text not null,
  month      text not null,
  ded_date   date not null,
  amount     numeric not null,
  reason     text,
  created_at timestamptz default now()
);

create table public.leaves (
  id         bigint generated always as identity primary key,
  username   text not null,
  month      text not null,
  leave_date date not null,
  paid       boolean default true,
  reason     text,
  created_at timestamptz default now(),
  unique (username, leave_date)         -- يمنع تكرار إجازة نفس اليوم
);

-- صف الإعدادات الوحيد
insert into public.settings (id) values (1) on conflict (id) do nothing;

-- فهارس للأداء
create index idx_attendance_user_month on public.attendance (username, month);
create index idx_attendance_date       on public.attendance (work_date);
create index idx_deductions_month      on public.deductions (month);
create index idx_leaves_month          on public.leaves (month);

-- ============================================================
-- (2) دوال مساعدة لتحديد هوية المتصل ودوره
-- ============================================================
create or replace function public.current_username()
returns text language sql stable security definer set search_path = public as $$
  select username from public.profiles where id = auth.uid()
$$;

create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin')
$$;

-- ============================================================
-- (3) تفعيل حماية الصفوف (RLS) — لا أحد يصل لأي صف إلا بما تسمح به السياسات
-- ============================================================
alter table public.profiles   enable row level security;
alter table public.attendance enable row level security;
alter table public.settings   enable row level security;
alter table public.deductions enable row level security;
alter table public.leaves     enable row level security;

-- ---------- profiles ----------
-- المدير يرى الجميع، والموظف يرى نفسه فقط
create policy profiles_select on public.profiles for select
  using ( public.is_admin() or id = auth.uid() );
-- التسجيل الذاتي: ينشئ المستخدم ملفه فقط وبدور موظف (لا يمكن منح نفسه صلاحية مدير)
create policy profiles_insert_self on public.profiles for insert
  with check ( id = auth.uid() and role = 'employee' );
-- التعديل/الحذف للمدير فقط (إنشاء/حذف الموظفين فعلياً يتم عبر دالة الإدارة)
create policy profiles_update_admin on public.profiles for update
  using ( public.is_admin() ) with check ( public.is_admin() );
create policy profiles_delete_admin on public.profiles for delete
  using ( public.is_admin() );

-- ---------- attendance ----------
create policy att_select on public.attendance for select
  using ( public.is_admin() or username = public.current_username() );
-- الموظف يسجّل بصمته فقط (وليست يدوية)، والمدير يضيف لأي أحد
create policy att_insert on public.attendance for insert
  with check ( public.is_admin() or (username = public.current_username() and coalesce(manual,false) = false) );
-- الموظف يغلق بصمته (punch_out فقط)، والمدير يعدّل الجميع
-- يمنع الموظف من تعديل punch_in أو تحويل السجل لـ manual
create policy att_update on public.attendance for update
  using ( public.is_admin() or username = public.current_username() )
  with check (
    public.is_admin()
    or (
      username = public.current_username()
      and coalesce(manual, false) = false
      -- الموظف يعدّل punch_out فقط: punch_in يجب أن يبقى كما هو
      -- هذا القيد يُطبَّق من جانب التطبيق؛ لتقييد الأعمدة بشكل صارم استخدم column-level security أو trigger
    )
  );
create policy att_delete on public.attendance for delete
  using ( public.is_admin() );

-- ---------- settings ----------
create policy settings_select on public.settings for select
  using ( auth.uid() is not null );           -- كل مستخدم مسجّل يقرأ النطاق والهوية
create policy settings_update on public.settings for update
  using ( public.is_admin() ) with check ( public.is_admin() );
create policy settings_insert on public.settings for insert
  with check ( public.is_admin() );

-- ---------- deductions ----------
create policy ded_select on public.deductions for select
  using ( public.is_admin() or username = public.current_username() );
create policy ded_admin_write on public.deductions for all
  using ( public.is_admin() ) with check ( public.is_admin() );

-- ---------- leaves ----------
create policy lv_select on public.leaves for select
  using ( public.is_admin() or username = public.current_username() );
create policy lv_admin_write on public.leaves for all
  using ( public.is_admin() ) with check ( public.is_admin() );

-- ============================================================
-- (3b) Trigger — يمنع الموظف من تعديل punch_in أو تحويل السجل لـ manual
-- ============================================================
create or replace function public.guard_attendance_update()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  -- المدير يمرّ بدون قيود
  if public.is_admin() then return new; end if;
  -- الموظف: لا يجوز تعديل punch_in أو رفع علامة manual
  if new.punch_in <> old.punch_in then
    raise exception 'not allowed to modify punch_in';
  end if;
  if coalesce(new.manual, false) <> coalesce(old.manual, false) then
    raise exception 'not allowed to modify manual flag';
  end if;
  return new;
end;
$$;

create trigger attendance_update_guard
  before update on public.attendance
  for each row execute function public.guard_attendance_update();

-- ============================================================
-- (4) التحديث اللحظي (Realtime) — لتصل التغييرات فوراً للأجهزة
-- ============================================================
alter publication supabase_realtime add table public.attendance;
alter publication supabase_realtime add table public.profiles;
alter publication supabase_realtime add table public.settings;
alter publication supabase_realtime add table public.deductions;
alter publication supabase_realtime add table public.leaves;

-- ============================================================
-- (4b) المكافآت — تُضاف إلى راتب الموظف (عكس الخصومات)
-- ============================================================
create table if not exists public.bonuses (
  id         bigint generated always as identity primary key,
  username   text not null,
  month      text not null,
  bonus_date date not null,
  amount     numeric not null,
  reason     text,
  created_at timestamptz default now()
);
create index if not exists idx_bonuses_month on public.bonuses (month);
alter table public.bonuses enable row level security;
create policy bon_select on public.bonuses for select
  using ( public.is_admin() or username = public.current_username() );
create policy bon_admin_write on public.bonuses for all
  using ( public.is_admin() ) with check ( public.is_admin() );
alter publication supabase_realtime add table public.bonuses;

-- ============================================================
-- (4c) منح الصلاحيات للأدوار الافتراضية في Supabase
-- ============================================================
grant usage on schema public to anon, authenticated;
grant all on all tables in schema public to anon, authenticated;
grant all on all sequences in schema public to anon, authenticated;
grant all on all routines in schema public to anon, authenticated;

-- ============================================================
-- (5) حساب المدير الأول
--   نفّذ هذا الجزء *بعد* إنشاء مستخدم admin@basma.local من:
--   Authentication → Users → Add user (مع تفعيل Auto Confirm User)
--   ثم شغّل السطر التالي لترقيته إلى مدير:
-- ============================================================
-- insert into public.profiles (id, username, name, role)
-- select id, 'admin', 'المدير', 'admin' from auth.users where email = 'admin@basma.local'
-- on conflict (id) do update set role = 'admin', username = 'admin';
