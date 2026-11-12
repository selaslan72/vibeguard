# Top Vibe-Coding Security Traps (and How to Catch Them)

AI coding assistants optimize for getting features working quickly. Without explicit security prompts, they consistently introduce the same high-severity anti-patterns. Check every applicable stack below during Phase 2.

---

## 1. Next.js / React / Vercel Traps
| Trap | What It Looks Like | Why It Breaks Security |
| :--- | :--- | :--- |
| **Unprotected Server Actions** | `"use server"` function `deletePost(id)` assumes only logged-in UI clicks it | Server Actions are public HTTP POST endpoints; anyone can invoke them directly with `curl`. |
| **Client-Only Route Guards** | `if (!user) redirect('/login')` inside a client component or `layout.tsx` | Attackers bypass the UI and hit `/api/*` or RSC payloads directly. |
| **Leaking Props in RSC** | Passing `const user = await prisma.user.findUnique(...)` to `<ClientComponent user={user} />` | Next.js serializes ALL props (including `passwordHash`, `apiKey`, `tokens`) into HTML script payloads. |
| **`NEXT_PUBLIC_` Secrets** | `NEXT_PUBLIC_OPENAI_KEY` or `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE` | Bundled into static client JS; visible in browser DevTools to every visitor. |

## 2. Supabase Traps
| Trap | What It Looks Like | Why It Breaks Security |
| :--- | :--- | :--- |
| **RLS Disabled on New Tables** | `CREATE TABLE invoices (...)` in SQL without `ENABLE ROW LEVEL SECURITY` | Anyone with the public `anon` key can read/edit/delete every row via Supabase REST API. |
| **Over-Broad Policies** | `CREATE POLICY "allow all" ON profiles FOR ALL USING (true)` | Any anonymous or signed-in user can overwrite any other user's profile. |
| **`service_role` in Client/Edge** | Importing admin client with `SUPABASE_SERVICE_ROLE_KEY` in browser/shared utils | Completely bypasses RLS across the entire database. |
| **Trusting `getSession()` on Server** | Reading `supabase.auth.getSession()` in API routes instead of `getUser()` | Cookie session data may not be re-verified against Supabase Auth server. |

## 3. Firebase Traps
| Trap | What It Looks Like | Why It Breaks Security |
| :--- | :--- | :--- |
| **Test-Mode Rules Left On** | `allow read, write: if true;` or expired timestamp bumped to 2099 | Public internet has full read/write/delete access to Firestore & Cloud Storage. |
| **Auth-Only Without Ownership** | `allow read, write: if request.auth != null;` on `/orders/{id}` | Any signed-up user can read or modify every other customer's orders. |
| **Client-Editable Role Fields** | Users allowed to `update` their own `/users/{uid}` doc without checking `!request.resource.data.diff(resource.data).affectedKeys().hasAny(['role', 'isPro', 'credits'])` | Any user can promote themselves to `admin` or grant unlimited credits from the browser console. |

## 4. Payments & Stripe Traps
| Trap | What It Looks Like | Why It Breaks Security |
| :--- | :--- | :--- |
| **Trusting Client Prices** | `stripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: req.body.price } }] })` | Attacker sends `price: 1` (1 cent) and buys a \$99 plan. |
| **Unverified Webhooks** | `const event = await req.json(); if (event.type === 'checkout.session.completed') ...` | Anyone can POST a fake `checkout.session.completed` payload and unlock paid accounts for free. |
| **Client-Triggered Upgrade** | `POST /api/upgrade-to-pro` called from success redirect page without verifying Stripe session status | Visiting `/success?session_id=123` or calling the API directly grants Pro access without paying. |

## 5. AI / LLM Wrapper Traps
| Trap | What It Looks Like | Why It Breaks Security |
| :--- | :--- | :--- |
| **Unauthenticated AI Proxy** | `/api/chat` forwards user messages to OpenAI/Gemini with no auth or rate limit | Bots discover `/api/chat` and drain your entire API billing limit in minutes. |
| **Direct Prompt Concatenation** | ``content: `You are helpful. User says: ${req.body.prompt}` `` inside `role: "system"` | Classic prompt injection overrides system boundaries and tool restrictions. |
| **Blind Code/HTML Execution** | Rendering LLM markdown via `dangerouslySetInnerHTML` or running generated code in `eval()`/`exec()` | Prompt injection becomes Stored/Reflected XSS or full server RCE. |
