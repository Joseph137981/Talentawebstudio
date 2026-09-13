create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text,
  role text not null default 'client' check (role in ('admin','client')),
  created_at timestamptz not null default now()
);

create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id,email,full_name,role)
  values (new.id,new.email,coalesce(new.raw_user_meta_data->>'full_name',''),
    case when lower(new.email)=lower('aliciakate018@gmail.com') then 'admin' else 'client' end)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

insert into public.profiles (id,email,full_name,role)
select id,email,coalesce(raw_user_meta_data->>'full_name',''),'admin'
from auth.users
where lower(email)=lower('aliciakate018@gmail.com')
on conflict (id) do update set role='admin';

create or replace function public.is_talenta_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists(select 1 from public.profiles where id=auth.uid() and role='admin');
$$;

create table if not exists public.projects (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  client_id uuid references auth.users(id) on delete set null,
  client_email text not null,
  client_name text,
  business_name text not null,
  title text not null default 'Website & Brand Project',
  package_name text,
  status text not null default 'Onboarding' check (status in ('Onboarding','Active','On hold','Completed','Cancelled')),
  stage text not null default 'Discovery' check (stage in ('Discovery','Content','Design','Development','Client review','Launch','Completed')),
  progress integer not null default 5 check (progress between 0 and 100),
  target_date date,
  invite_code uuid not null default gen_random_uuid() unique
);

create table if not exists public.project_briefs (
  project_id uuid primary key references public.projects(id) on delete cascade,
  client_id uuid not null references auth.users(id) on delete cascade,
  answers jsonb not null default '{}'::jsonb,
  completed_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.project_updates (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects(id) on delete cascade,
  author_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  message text not null,
  stage text,
  progress integer check (progress between 0 and 100),
  preview_url text,
  created_at timestamptz not null default now()
);

create table if not exists public.change_requests (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects(id) on delete cascade,
  client_id uuid not null references auth.users(id) on delete cascade,
  subject text not null,
  message text not null,
  reference_url text,
  status text not null default 'New' check (status in ('New','Reviewing','Approved','In progress','Completed','Declined','Additional payment required')),
  admin_response text,
  additional_cost_cents integer check (additional_cost_cents is null or additional_cost_cents >= 0),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.invoices (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects(id) on delete cascade,
  description text not null,
  amount_cents integer not null check (amount_cents > 0),
  due_date date,
  payment_url text not null,
  status text not null default 'Due' check (status in ('Draft','Due','Paid','Cancelled')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.touch_updated_at()
returns trigger language plpgsql set search_path = public as $$
begin new.updated_at=now();return new;end;
$$;

do $$ begin
  create trigger projects_touch before update on public.projects for each row execute function public.touch_updated_at();
exception when duplicate_object then null; end $$;
do $$ begin
  create trigger briefs_touch before update on public.project_briefs for each row execute function public.touch_updated_at();
exception when duplicate_object then null; end $$;
do $$ begin
  create trigger requests_touch before update on public.change_requests for each row execute function public.touch_updated_at();
exception when duplicate_object then null; end $$;
do $$ begin
  create trigger invoices_touch before update on public.invoices for each row execute function public.touch_updated_at();
exception when duplicate_object then null; end $$;

alter table public.profiles enable row level security;
alter table public.projects enable row level security;
alter table public.project_briefs enable row level security;
alter table public.project_updates enable row level security;
alter table public.change_requests enable row level security;
alter table public.invoices enable row level security;

drop policy if exists "Profiles visible to owner or admin" on public.profiles;
create policy "Profiles visible to owner or admin" on public.profiles for select to authenticated
using (id=auth.uid() or public.is_talenta_admin());

drop policy if exists "Admins manage projects" on public.projects;
create policy "Admins manage projects" on public.projects for all to authenticated
using (public.is_talenta_admin()) with check (public.is_talenta_admin());
drop policy if exists "Clients view their projects" on public.projects;
create policy "Clients view their projects" on public.projects for select to authenticated
using (client_id=auth.uid());

drop policy if exists "Admins manage briefs" on public.project_briefs;
create policy "Admins manage briefs" on public.project_briefs for all to authenticated
using (public.is_talenta_admin()) with check (public.is_talenta_admin());
drop policy if exists "Clients view own brief" on public.project_briefs;
create policy "Clients view own brief" on public.project_briefs for select to authenticated
using (client_id=auth.uid());
drop policy if exists "Clients create own brief" on public.project_briefs;
create policy "Clients create own brief" on public.project_briefs for insert to authenticated
with check (client_id=auth.uid() and exists(select 1 from public.projects p where p.id=project_id and p.client_id=auth.uid()));
drop policy if exists "Clients update own brief" on public.project_briefs;
create policy "Clients update own brief" on public.project_briefs for update to authenticated
using (client_id=auth.uid()) with check (client_id=auth.uid());

drop policy if exists "Admins manage updates" on public.project_updates;
create policy "Admins manage updates" on public.project_updates for all to authenticated
using (public.is_talenta_admin()) with check (public.is_talenta_admin());
drop policy if exists "Clients view project updates" on public.project_updates;
create policy "Clients view project updates" on public.project_updates for select to authenticated
using (exists(select 1 from public.projects p where p.id=project_id and p.client_id=auth.uid()));

drop policy if exists "Admins manage change requests" on public.change_requests;
create policy "Admins manage change requests" on public.change_requests for all to authenticated
using (public.is_talenta_admin()) with check (public.is_talenta_admin());
drop policy if exists "Clients view own requests" on public.change_requests;
create policy "Clients view own requests" on public.change_requests for select to authenticated
using (client_id=auth.uid());
drop policy if exists "Clients create requests" on public.change_requests;
create policy "Clients create requests" on public.change_requests for insert to authenticated
with check (client_id=auth.uid() and exists(select 1 from public.projects p where p.id=project_id and p.client_id=auth.uid()));

drop policy if exists "Admins manage invoices" on public.invoices;
create policy "Admins manage invoices" on public.invoices for all to authenticated
using (public.is_talenta_admin()) with check (public.is_talenta_admin());
drop policy if exists "Clients view invoices" on public.invoices;
create policy "Clients view invoices" on public.invoices for select to authenticated
using (exists(select 1 from public.projects p where p.id=project_id and p.client_id=auth.uid()));

create or replace function public.claim_project(p_invite_code uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare v_project_id uuid;v_email text;
begin
  if auth.uid() is null then raise exception 'You must be signed in.';end if;
  v_email:=lower(coalesce(auth.jwt()->>'email',''));
  update public.projects
  set client_id=auth.uid()
  where invite_code=p_invite_code and client_id is null and lower(client_email)=v_email
  returning id into v_project_id;
  if v_project_id is null then
    select id into v_project_id from public.projects where invite_code=p_invite_code and client_id=auth.uid();
  end if;
  if v_project_id is null then raise exception 'This invitation does not match your signed-in email.';end if;
  return v_project_id;
end;
$$;

revoke all on function public.claim_project(uuid) from public;
revoke all on function public.is_talenta_admin() from public;
grant execute on function public.claim_project(uuid) to authenticated;
grant execute on function public.is_talenta_admin() to authenticated;
