-- =====================================================================
-- Habitué — base de données (à coller dans Supabase > SQL Editor > Run)
-- Peut être relancé sans risque : il ne supprime aucune donnée.
-- =====================================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- ---------- TABLES ----------

-- Un commerçant = un compte Supabase Auth
create table if not exists public.merchants (
  id uuid primary key references auth.users(id) on delete cascade,
  business_name text not null check (char_length(business_name) between 2 and 80),
  pin_hash text not null,
  created_at timestamptz not null default now()
);

-- La carte de fidélité du commerçant (une seule par commerce dans le MVP)
create table if not exists public.cards (
  id uuid primary key default gen_random_uuid(),
  merchant_id uuid not null unique references public.merchants(id) on delete cascade,
  stamps_required int not null check (stamps_required between 3 and 20),
  reward text not null check (char_length(reward) between 2 and 80),
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Les clients finaux (pas de compte : un jeton secret gardé dans leur téléphone)
create table if not exists public.customers (
  id uuid primary key default gen_random_uuid(),
  card_id uuid not null references public.cards(id) on delete cascade,
  merchant_id uuid not null references public.merchants(id) on delete cascade,
  first_name text not null check (char_length(first_name) between 1 and 40),
  contact text not null check (char_length(contact) between 5 and 120),
  token_hash text not null,
  stamps int not null default 0,
  rewards_earned int not null default 0,
  created_at timestamptz not null default now(),
  last_visit_at timestamptz,
  unique (card_id, contact)
);
create index if not exists customers_token_idx on public.customers(token_hash);
create index if not exists customers_merchant_idx on public.customers(merchant_id);

-- Historique : chaque tampon et chaque récompense
create table if not exists public.stamps (
  id bigint generated always as identity primary key,
  customer_id uuid not null references public.customers(id) on delete cascade,
  merchant_id uuid not null references public.merchants(id) on delete cascade,
  kind text not null check (kind in ('stamp','reward')),
  created_at timestamptz not null default now()
);
create index if not exists stamps_merchant_idx on public.stamps(merchant_id, created_at desc);

-- Essais de code PIN ratés (anti-triche)
create table if not exists public.pin_failures (
  id bigint generated always as identity primary key,
  customer_id uuid not null references public.customers(id) on delete cascade,
  merchant_id uuid not null references public.merchants(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists pin_failures_idx on public.pin_failures(merchant_id, created_at);

-- Messages du formulaire de contact
create table if not exists public.contact_messages (
  id bigint generated always as identity primary key,
  name text not null,
  email text not null,
  message text not null,
  created_at timestamptz not null default now()
);

-- Administrateurs du service (toi). On y ajoute ton compte à la main.
create table if not exists public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

-- ---------- SÉCURITÉ : personne ne touche aux tables directement ----------

alter table public.merchants enable row level security;
alter table public.cards enable row level security;
alter table public.customers enable row level security;
alter table public.stamps enable row level security;
alter table public.pin_failures enable row level security;
alter table public.contact_messages enable row level security;
alter table public.admins enable row level security;

revoke all on public.merchants, public.cards, public.customers, public.stamps,
  public.pin_failures, public.contact_messages, public.admins from anon, authenticated;

-- Un commerçant connecté peut LIRE ses propres données (jamais le PIN ni les jetons)
grant select (id, business_name, created_at) on public.merchants to authenticated;
grant select on public.cards to authenticated;
grant select (id, card_id, merchant_id, first_name, contact, stamps, rewards_earned, created_at, last_visit_at)
  on public.customers to authenticated;
grant delete on public.customers to authenticated;
grant select on public.stamps to authenticated;

drop policy if exists merchants_own on public.merchants;
create policy merchants_own on public.merchants for select to authenticated using (id = auth.uid());
drop policy if exists cards_own on public.cards;
create policy cards_own on public.cards for select to authenticated using (merchant_id = auth.uid());
drop policy if exists customers_own on public.customers;
create policy customers_own on public.customers for select to authenticated using (merchant_id = auth.uid());
drop policy if exists customers_delete_own on public.customers;
create policy customers_delete_own on public.customers for delete to authenticated using (merchant_id = auth.uid());
drop policy if exists stamps_own on public.stamps;
create policy stamps_own on public.stamps for select to authenticated using (merchant_id = auth.uid());

-- ---------- FONCTIONS (toutes les écritures passent par ici) ----------

-- Commerçant : créer ou modifier son commerce et sa carte.
-- p_pin peut être vide lors d'une modification (on garde l'ancien).
create or replace function public.save_merchant(
  p_business_name text, p_pin text, p_stamps_required int, p_reward text, p_active boolean default true
) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_uid uuid := auth.uid();
  v_card uuid;
  v_exists boolean;
begin
  if v_uid is null then raise exception 'NOT_LOGGED_IN'; end if;
  p_business_name := btrim(coalesce(p_business_name, ''));
  p_reward := btrim(coalesce(p_reward, ''));
  if char_length(p_business_name) not between 2 and 80 then raise exception 'BAD_NAME'; end if;
  if char_length(p_reward) not between 2 and 80 then raise exception 'BAD_REWARD'; end if;
  if p_stamps_required is null or p_stamps_required not between 3 and 20 then raise exception 'BAD_STAMPS'; end if;
  select true into v_exists from merchants where id = v_uid;
  if p_pin is not null and p_pin <> '' and p_pin !~ '^[0-9]{4,6}$' then raise exception 'BAD_PIN'; end if;
  if v_exists is null then
    if p_pin is null or p_pin = '' then raise exception 'BAD_PIN'; end if;
    insert into merchants(id, business_name, pin_hash)
      values (v_uid, p_business_name, crypt(p_pin, gen_salt('bf')));
  else
    update merchants set business_name = p_business_name,
      pin_hash = case when p_pin is null or p_pin = '' then pin_hash else crypt(p_pin, gen_salt('bf')) end
      where id = v_uid;
  end if;
  insert into cards(merchant_id, stamps_required, reward, active)
    values (v_uid, p_stamps_required, p_reward, coalesce(p_active, true))
    on conflict (merchant_id) do update
      set stamps_required = excluded.stamps_required, reward = excluded.reward, active = excluded.active
    returning id into v_card;
  -- si on baisse le nombre de tampons, personne ne dépasse le nouveau maximum
  update customers set stamps = p_stamps_required where card_id = v_card and stamps > p_stamps_required;
  return v_card;
end $$;

-- Public : infos d'une carte (page affichée après scan du QR code)
create or replace function public.get_card_public(p_card_id uuid)
returns table (business_name text, stamps_required int, reward text, active boolean)
language sql stable security definer set search_path = public as $$
  select m.business_name, c.stamps_required, c.reward, c.active
  from cards c join merchants m on m.id = c.merchant_id where c.id = p_card_id;
$$;

-- Public : un client rejoint une carte. Renvoie un jeton secret à garder dans le téléphone.
create or replace function public.join_card(p_card_id uuid, p_first_name text, p_contact text)
returns text
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_card cards%rowtype;
  v_token text := encode(gen_random_bytes(24), 'hex');
  v_hash text := encode(digest(v_token, 'sha256'), 'hex');
  v_today int;
begin
  p_first_name := btrim(coalesce(p_first_name, ''));
  p_contact := lower(regexp_replace(btrim(coalesce(p_contact, '')), '\s+', '', 'g'));
  if char_length(p_first_name) not between 1 and 40 then raise exception 'BAD_NAME'; end if;
  if p_contact !~ '^[^@\s]+@[^@\s]+\.[a-z]{2,}$' and p_contact !~ '^\+?[0-9]{9,15}$' then
    raise exception 'BAD_CONTACT';
  end if;
  select * into v_card from cards where id = p_card_id;
  if not found or not v_card.active then raise exception 'CARD_NOT_FOUND'; end if;
  -- client déjà inscrit (nouveau téléphone, cache vidé) : on lui redonne accès à sa carte
  update customers set token_hash = v_hash where card_id = p_card_id and contact = p_contact;
  if found then return v_token; end if;
  select count(*) into v_today from customers where card_id = p_card_id and created_at > now() - interval '1 day';
  if v_today >= 300 then raise exception 'TOO_MANY'; end if;
  insert into customers(card_id, merchant_id, first_name, contact, token_hash)
    values (p_card_id, v_card.merchant_id, p_first_name, p_contact, v_hash);
  return v_token;
end $$;

-- Public : le client consulte sa carte avec son jeton
create or replace function public.get_my_card(p_token text)
returns table (first_name text, stamps int, rewards_earned int, business_name text,
               stamps_required int, reward text, active boolean)
language sql stable security definer set search_path = public, extensions as $$
  select cu.first_name, cu.stamps, cu.rewards_earned, m.business_name, c.stamps_required, c.reward, c.active
  from customers cu join cards c on c.id = cu.card_id join merchants m on m.id = c.merchant_id
  where cu.token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex');
$$;

-- Public : le commerçant tape son PIN sur le téléphone du client.
-- Ajoute un tampon, ou remet la carte à zéro si la récompense est utilisée.
create or replace function public.add_stamp(p_token text, p_pin text)
returns table (status text, stamps int, stamps_required int)
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_cu customers%rowtype;
  v_card cards%rowtype;
  v_pin_hash text;
  v_fail_customer int;
  v_fail_merchant int;
begin
  select * into v_cu from customers
    where token_hash = encode(digest(coalesce(p_token, ''), 'sha256'), 'hex') for update;
  if not found then raise exception 'CARD_NOT_FOUND'; end if;
  select * into v_card from cards where id = v_cu.card_id;
  if not v_card.active then raise exception 'CARD_INACTIVE'; end if;

  select count(*) into v_fail_customer from pin_failures
    where customer_id = v_cu.id and created_at > now() - interval '15 minutes';
  select count(*) into v_fail_merchant from pin_failures
    where merchant_id = v_cu.merchant_id and created_at > now() - interval '1 hour';
  if v_fail_customer >= 5 or v_fail_merchant >= 50 then
    return query select 'LOCKED'::text, v_cu.stamps, v_card.stamps_required; return;
  end if;

  select pin_hash into v_pin_hash from merchants where id = v_cu.merchant_id;
  if p_pin is null or p_pin !~ '^[0-9]{4,6}$' or crypt(p_pin, v_pin_hash) <> v_pin_hash then
    insert into pin_failures(customer_id, merchant_id) values (v_cu.id, v_cu.merchant_id);
    return query select 'WRONG_PIN'::text, v_cu.stamps, v_card.stamps_required; return;
  end if;

  -- anti double-clic
  if v_cu.last_visit_at is not null and v_cu.last_visit_at > now() - interval '5 seconds' then
    return query select 'TOO_FAST'::text, v_cu.stamps, v_card.stamps_required; return;
  end if;

  if v_cu.stamps >= v_card.stamps_required then
    update customers set stamps = 0, rewards_earned = rewards_earned + 1, last_visit_at = now() where id = v_cu.id;
    insert into stamps(customer_id, merchant_id, kind) values (v_cu.id, v_cu.merchant_id, 'reward');
    return query select 'REWARD_USED'::text, 0, v_card.stamps_required; return;
  end if;

  update customers set stamps = customers.stamps + 1, last_visit_at = now() where id = v_cu.id;
  insert into stamps(customer_id, merchant_id, kind) values (v_cu.id, v_cu.merchant_id, 'stamp');
  return query select (case when v_cu.stamps + 1 >= v_card.stamps_required then 'REWARD_READY' else 'STAMPED' end)::text,
    v_cu.stamps + 1, v_card.stamps_required;
end $$;

-- Public : formulaire de contact (limité à 30 messages par heure au total)
create or replace function public.submit_contact(p_name text, p_email text, p_message text)
returns void
language plpgsql security definer set search_path = public as $$
begin
  p_name := btrim(coalesce(p_name, '')); p_email := lower(btrim(coalesce(p_email, '')));
  p_message := btrim(coalesce(p_message, ''));
  if char_length(p_name) not between 1 and 80 then raise exception 'BAD_NAME'; end if;
  if p_email !~ '^[^@\s]+@[^@\s]+\.[a-z]{2,}$' or char_length(p_email) > 120 then raise exception 'BAD_EMAIL'; end if;
  if char_length(p_message) not between 5 and 2000 then raise exception 'BAD_MESSAGE'; end if;
  if (select count(*) from contact_messages where created_at > now() - interval '1 hour') >= 30 then
    raise exception 'TOO_MANY';
  end if;
  insert into contact_messages(name, email, message) values (p_name, p_email, p_message);
end $$;

-- Commerçant : supprimer définitivement son compte et toutes ses données (RGPD)
create or replace function public.delete_my_account()
returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'NOT_LOGGED_IN'; end if;
  delete from auth.users where id = auth.uid();
end $$;

-- Admin : suis-je administrateur ?
create or replace function public.is_admin()
returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from admins where user_id = auth.uid());
$$;

-- Admin : vue d'ensemble des commerçants
create or replace function public.admin_overview()
returns table (merchant_id uuid, business_name text, email text, created_at timestamptz,
               customers bigint, stamps_30d bigint, last_activity timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'FORBIDDEN'; end if;
  return query
    select m.id, m.business_name, u.email::text, m.created_at,
      (select count(*) from customers cu where cu.merchant_id = m.id),
      (select count(*) from stamps s where s.merchant_id = m.id and s.created_at > now() - interval '30 days'),
      (select max(s.created_at) from stamps s where s.merchant_id = m.id)
    from merchants m join auth.users u on u.id = m.id
    order by m.created_at desc;
end $$;

-- Admin : messages de contact reçus
create or replace function public.admin_messages()
returns table (id bigint, name text, email text, message text, created_at timestamptz)
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'FORBIDDEN'; end if;
  return query select cm.id, cm.name, cm.email, cm.message, cm.created_at
    from contact_messages cm order by cm.created_at desc limit 200;
end $$;

-- ---------- QUI A LE DROIT D'APPELER QUOI ----------
revoke all on function public.save_merchant(text,text,int,text,boolean) from public, anon;
revoke all on function public.delete_my_account() from public, anon;
revoke all on function public.is_admin() from public, anon;
revoke all on function public.admin_overview() from public, anon;
revoke all on function public.admin_messages() from public, anon;
grant execute on function public.save_merchant(text,text,int,text,boolean) to authenticated;
grant execute on function public.delete_my_account() to authenticated;
grant execute on function public.is_admin() to authenticated;
grant execute on function public.admin_overview() to authenticated;
grant execute on function public.admin_messages() to authenticated;
grant execute on function public.get_card_public(uuid) to anon, authenticated;
grant execute on function public.join_card(uuid,text,text) to anon, authenticated;
grant execute on function public.get_my_card(text) to anon, authenticated;
grant execute on function public.add_stamp(text,text) to anon, authenticated;
grant execute on function public.submit_contact(text,text,text) to anon, authenticated;
