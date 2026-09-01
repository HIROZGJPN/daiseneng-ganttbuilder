-- 工程表ビルダー: クラウド保存機能のセットアップスクリプト
-- Supabaseの SQL Editor で「一度だけ」実行してください。
--
-- 実行前に、下の CHANGE_ME_PASSCODE を実際に使う合言葉に書き換えてください。
-- （このスクリプトを再実行すると合言葉は上書きされます）

create extension if not exists pgcrypto;

create table if not exists public.schedules (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  data jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.app_config (
  key text primary key,
  value text not null
);

alter table public.schedules enable row level security;
alter table public.app_config enable row level security;

-- ポリシーを一切作らないことで anon / authenticated からの直接アクセスを
-- すべて拒否する。念のためデフォルトのテーブル権限も明示的に剥奪しておく。
revoke all on public.schedules from anon, authenticated;
revoke all on public.app_config from anon, authenticated;

-- ここを実際の合言葉に書き換えてから実行してください。
insert into public.app_config (key, value)
values ('cloud_passcode_hash', crypt('CHANGE_ME_PASSCODE', gen_salt('bf')))
on conflict (key) do update set value = excluded.value;

create or replace function public.verify_cloud_passcode(p_passcode text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  h text;
begin
  select value into h from app_config where key = 'cloud_passcode_hash';
  if h is null then
    return false;
  end if;
  return h = crypt(p_passcode, h);
end;
$$;

create or replace function public.schedules_list(p_passcode text)
returns table(id uuid, name text, updated_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
begin
  if not verify_cloud_passcode(p_passcode) then
    raise exception 'invalid passcode';
  end if;
  return query select s.id, s.name, s.updated_at from schedules s order by s.updated_at desc;
end;
$$;

create or replace function public.schedules_load(p_passcode text, p_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  d jsonb;
begin
  if not verify_cloud_passcode(p_passcode) then
    raise exception 'invalid passcode';
  end if;
  select data into d from schedules where id = p_id;
  return d;
end;
$$;

create or replace function public.schedules_save(p_passcode text, p_id uuid, p_name text, p_data jsonb)
returns uuid
language plpgsql
security definer
set search_path = public
as $$
declare
  new_id uuid;
begin
  if not verify_cloud_passcode(p_passcode) then
    raise exception 'invalid passcode';
  end if;
  if p_id is null then
    insert into schedules(name, data) values (p_name, p_data) returning id into new_id;
    return new_id;
  else
    update schedules set name = p_name, data = p_data, updated_at = now() where id = p_id;
    return p_id;
  end if;
end;
$$;

create or replace function public.schedules_delete(p_passcode text, p_id uuid)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if not verify_cloud_passcode(p_passcode) then
    raise exception 'invalid passcode';
  end if;
  delete from schedules where id = p_id;
end;
$$;

revoke all on function public.verify_cloud_passcode(text) from anon, authenticated, public;
grant execute on function public.schedules_list(text) to anon, authenticated;
grant execute on function public.schedules_load(text, uuid) to anon, authenticated;
grant execute on function public.schedules_save(text, uuid, text, jsonb) to anon, authenticated;
grant execute on function public.schedules_delete(text, uuid) to anon, authenticated;
