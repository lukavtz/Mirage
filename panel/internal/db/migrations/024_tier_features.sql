INSERT INTO settings (key, value) VALUES
    ('pricing_starter', '{"max_bots":1,"max_users":1,"smart_filters":false,"api_limited":true,"postgresql":false,"clipper_module":false,"loader_module":false,"price_monthly":7000,"price_lifetime":70000}'),
    ('pricing_pro', '{"max_bots":7,"max_users":5,"smart_filters":true,"api_limited":true,"postgresql":false,"clipper_module":true,"loader_module":true,"price_monthly":15000,"price_lifetime":150000}'),
    ('pricing_team', '{"max_bots":15,"max_users":20,"smart_filters":true,"api_limited":false,"postgresql":true,"clipper_module":true,"loader_module":true,"price_monthly":35000,"price_lifetime":350000}')
ON CONFLICT (key) DO NOTHING;
