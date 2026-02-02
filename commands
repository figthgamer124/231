




@bot.command(name='backup')
async def backup_server(ctx):
    """Backup the current server, including category/channel structure and simple overwrites."""
    if not ctx.guild:
        await ctx.send("This command only works in a server!")
        return

    guild = ctx.guild
    backup_data = {
        'name': guild.name,
        'timestamp': datetime.now().isoformat(),
        'categories': [],
        'channels': [],
        'roles': []
    }

    # Backup categories (including overwrites and position)
    for cat in guild.categories:
        cat_data = {
            'name': cat.name,
            'position': getattr(cat, 'position', None),
            'overwrites': {}
        }
        for target, overwrite in getattr(cat, 'overwrites', {}).items():
            try:
                allow, deny = overwrite.pair()
                allow_v = allow.value if allow else 0
                deny_v = deny.value if deny else 0
                if isinstance(target, discord.Role):
                    cat_data['overwrites'][target.name] = {'allow': allow_v, 'deny': deny_v}
                elif target == guild.default_role:
                    cat_data['overwrites']['everyone'] = {'allow': allow_v, 'deny': deny_v}
            except Exception:
                pass
        backup_data['categories'].append(cat_data)

    # Backup channels (including category reference, position and overwrites)
    for channel in guild.channels:
        channel_data = {
            'name': channel.name,
            'type': getattr(channel.type, 'name', str(channel.type)),
            'category': channel.category.name if getattr(channel, 'category', None) else None,
            'position': getattr(channel, 'position', None),
            'topic': getattr(channel, 'topic', None),
            'nsfw': getattr(channel, 'nsfw', False),
            'bitrate': getattr(channel, 'bitrate', None),
            'user_limit': getattr(channel, 'user_limit', None),
            'rate_limit_per_user': getattr(channel, 'rate_limit_per_user', None),
            'overwrites': {},
            'messages': []
        }

        # Record role overwrites (serialize by role name as allow/deny ints)
        for target, overwrite in getattr(channel, 'overwrites', {}).items():
            try:
                allow, deny = overwrite.pair()
                allow_v = allow.value if allow else 0
                deny_v = deny.value if deny else 0
                if isinstance(target, discord.Role):
                    channel_data['overwrites'][target.name] = {'allow': allow_v, 'deny': deny_v}
                elif target == guild.default_role:
                    channel_data['overwrites']['everyone'] = {'allow': allow_v, 'deny': deny_v}
            except Exception:
                # ignore non-role overwrites
                pass

        if isinstance(channel, discord.TextChannel):
            async for message in channel.history(limit=100):
                channel_data['messages'].append({
                    'author': getattr(message.author, 'name', str(message.author)),
                    'content': message.content,
                    'timestamp': message.created_at.isoformat()
                })

        backup_data['channels'].append(channel_data)

    # Backup roles (include permissions, hoist, mentionable, position)
    for role in guild.roles:
        try:
            backup_data['roles'].append({
                'name': role.name,
                'color': role.color.value,
                'permissions': getattr(role.permissions, 'value', 0),
                'hoist': role.hoist,
                'mentionable': role.mentionable,
                'position': getattr(role, 'position', None)
            })
        except Exception:
            backup_data['roles'].append({'name': role.name, 'color': role.color.value})

    # Add guild id to the backup so it can be server-locked
    backup_data['guild_id'] = guild.id

    # Generate a random restore key and store only its SHA-256 hash in the backup
    # This key is sent to the user who created the backup and is required to restore
    try:
        restore_key = secrets.token_urlsafe(16)
        backup_data['restore_hash'] = hashlib.sha256(restore_key.encode('utf-8')).hexdigest()
    except Exception:
        restore_key = None

    # Save to file
    filename = f"{BACKUP_DIR}/{guild.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(backup_data, f, indent=2, ensure_ascii=False)

    # DM the user the restore key (if generated) so they can reuse this backup on other servers
    # Send only the backup filename, server name, and restore key (each on its own line)
    if restore_key:
        try:
            try:
                short_name = os.path.basename(filename)
                await ctx.author.send(f"File: **{short_name}**\nServer: **{guild.name}**\nRestore Key: **{restore_key}**")
            except Exception:
                # fall back to channel notice if DM fails
                await ctx.send("⚠️ I attempted to DM you the restore key but couldn't. Keep the backup file safe; if you want cross-server restores, ensure you can receive DMs from me.")
        except Exception:
            pass

    await ctx.send(f"✅ Server backed up check DMs for the restore key! Backup file")

@bot.command(name='restore')
@commands.has_permissions(administrator=True)
@commands.bot_has_guild_permissions(manage_roles=True, manage_channels=True)
async def restore_server(ctx, filename: str, mode: str = "", password: str = ""):
    """Restore a server from backup.

    Modes:
     - `dry`  : preview only (no changes)
     - `force`: create items even if they already exist (creates timestamped copies)
    
    If the backup was created for a different guild the restore key (password) is required.
    """
    if not ctx.guild:
        await ctx.send("This command only works in a server!")
        return

    filepath = f"{BACKUP_DIR}/{filename}"
    if not os.path.exists(filepath):
        await ctx.send(f"❌ Backup file not found: `{filename}`")
        return

    with open(filepath, 'r', encoding='utf-8') as f:
        backup_data = json.load(f)

    # If the backup includes a guild_id, enforce server-lock: if the backup guild differs
    # from the current guild then a password (the restore key) is required to proceed.
    try:
        b_gid = backup_data.get('guild_id')
        restore_hash = backup_data.get('restore_hash')
    except Exception:
        b_gid = None
        restore_hash = None

    if b_gid and b_gid != ctx.guild.id:
        # backup is from a different server
        if not restore_hash:
            await ctx.send("❌ This backup was created for a different server and is locked (no restore key present). Cannot restore.")
            return
        if not password:
            await ctx.send("🔐 This backup was created for a different server. Provide the restore key to restore it here. Usage: `!restore <filename> <mode> <restore_key>` (e.g. `!restore backup.json force <restore_key>`) ")
            return
        # verify password
        try:
            supplied_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
            if supplied_hash != restore_hash:
                await ctx.send("❌ Invalid restore key. Cannot restore this backup.")
                return
        except Exception:
            await ctx.send("⚠️ Error validating restore key. Cannot restore.")
            return

    # If backup contains a restore_hash but was made for this same guild, allow restore without password
    # (the key is primarily to prevent cross-server restores)

    # parse modes early so we can reference them (avoid UnboundLocalError)
    dry_run = (mode or "").lower() == "dry"
    force_mode = (mode or "").lower() == "force"

    await ctx.send(f"📋 Restoring from {backup_data.get('timestamp', 'unknown timestamp')}...")
    if force_mode:
        try:
            await ctx.send("⚠️ Force mode enabled — conflicting items will be created with a '-restored-<timestamp>' suffix.")
        except Exception:
            pass

    roles = backup_data.get('roles', [])
    created_roles = []
    skipped_roles = []
    failed_roles = []

    created_channels = []
    skipped_channels = []
    failed_channels = []

    # Create roles first (preserve permissions, hoist, mentionable)
    created_role_infos = []  # tuples (name, position, role_obj)
    for role_data in roles:
        name = role_data.get('name') or 'Unnamed'
        color_val = role_data.get('color', 0) or 0
        perm_val = role_data.get('permissions', 0) or 0
        hoist = role_data.get('hoist', False)
        mentionable = role_data.get('mentionable', False)
        position = role_data.get('position')
        existing = discord.utils.get(ctx.guild.roles, name=name)
        if existing:
            skipped_roles.append(name)
            continue
        try:
            if dry_run:
                created_roles.append(name)
                created_role_infos.append((name, position, None))
            else:
                new_role = await ctx.guild.create_role(name=name, color=discord.Color(color_val), permissions=discord.Permissions(value=perm_val), hoist=hoist, mentionable=mentionable)
                created_roles.append(name)
                created_role_infos.append((name, position, new_role))
        except discord.Forbidden:
            failed_roles.append(f"{name} (Forbidden) - check bot's Manage Roles permission and role hierarchy")
            await ctx.send(f"❌ Missing permission to create role '{name}'. Make sure my role is higher than the roles you're trying to create and that I have Manage Roles.")
        except Exception as e:
            failed_roles.append(f"{name} ({e})")
            print(f"Error creating role {name}: {e}")

    # Try to set role positions (best-effort)
    if not dry_run:
        for name, pos, role_obj in created_role_infos:
            if role_obj and pos is not None:
                try:
                    await role_obj.edit(position=pos)
                except Exception as e:
                    print(f"Failed to set role position for {name}: {e}")
                    # we don't fail the whole restore for this


    # Now create categories from backup (preserve position and overwrites)
    categories = backup_data.get('categories', [])
    created_categories = []
    skipped_categories = []
    failed_categories = []

    for cat in categories:
        name = cat.get('name')
        existing_cat = discord.utils.get(ctx.guild.categories, name=name)
        if existing_cat:
            if force_mode:
                # Create a timestamped copy instead of skipping
                new_name = f"{name}-restored-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                if dry_run:
                    created_categories.append(f"{new_name} (would be created, original exists)")
                else:
                    try:
                        new_cat = await ctx.guild.create_category(name=new_name)
                        created_categories.append(new_name)
                        # apply position if available
                        if cat.get('position') is not None:
                            try:
                                await new_cat.edit(position=cat.get('position'))
                            except Exception as e:
                                print(f"Failed to set category position for {new_name}: {e}")
                        # apply overwrites
                        for role_name, perms in (cat.get('overwrites') or {}).items():
                            role_obj = discord.utils.get(ctx.guild.roles, name=role_name) if role_name != 'everyone' else ctx.guild.default_role
                            if role_obj:
                                try:
                                    allow_v = perms.get('allow', 0)
                                    deny_v = perms.get('deny', 0)
                                    allow_p = discord.Permissions(value=allow_v)
                                    deny_p = discord.Permissions(value=deny_v)
                                    overwrite = discord.PermissionOverwrite.from_pair(allow_p, deny_p)
                                    await new_cat.set_permissions(role_obj, overwrite=overwrite)
                                except Exception as e:
                                    print(f"Failed to set overwrite on category {new_name}: {e}")
                    except Exception as e:
                        failed_categories.append(f"Category (force create): {new_name} ({e})")
            else:
                skipped_categories.append(name)
                # still apply overwrites if present
                if not dry_run:
                    for role_name, perms in (cat.get('overwrites') or {}).items():
                        role_obj = discord.utils.get(ctx.guild.roles, name=role_name) if role_name != 'everyone' else ctx.guild.default_role
                        if role_obj:
                            try:
                                allow_v = perms.get('allow', 0)
                                deny_v = perms.get('deny', 0)
                                allow_p = discord.Permissions(value=allow_v)
                                deny_p = discord.Permissions(value=deny_v)
                                overwrite = discord.PermissionOverwrite.from_pair(allow_p, deny_p)
                                await existing_cat.set_permissions(role_obj, overwrite=overwrite)
                            except Exception as e:
                                print(f"Failed to set overwrite on category {name}: {e}")
            continue
        try:
            if dry_run:
                created_categories.append(name)
            else:
                new_cat = await ctx.guild.create_category(name=name)
                created_categories.append(name)
                # apply position if available
                if cat.get('position') is not None:
                    try:
                        await new_cat.edit(position=cat.get('position'))
                    except Exception as e:
                        print(f"Failed to set category position for {name}: {e}")
                # apply overwrites
                for role_name, perms in (cat.get('overwrites') or {}).items():
                    role_obj = discord.utils.get(ctx.guild.roles, name=role_name) if role_name != 'everyone' else ctx.guild.default_role
                    if role_obj:
                        try:
                            allow_v = perms.get('allow', 0)
                            deny_v = perms.get('deny', 0)
                            allow_p = discord.Permissions(value=allow_v)
                            deny_p = discord.Permissions(value=deny_v)
                            overwrite = discord.PermissionOverwrite.from_pair(allow_p, deny_p)
                            await new_cat.set_permissions(role_obj, overwrite=overwrite)
                        except Exception as e:
                            print(f"Failed to set overwrite on category {name}: {e}")
        except Exception as e:
            failed_categories.append(f"Category: {name} ({e})")
            await ctx.send(f"⚠️ Failed to create category {name}: {e}")

    # Helper to lookup category object by name
    def find_category(guild, name):
        return discord.utils.get(guild.categories, name=name)

    # Then channels
    for ch in backup_data.get('channels', []):
        ch_type = (ch.get('type') or '').lower()
        name = ch.get('name')
        existing = discord.utils.get(ctx.guild.channels, name=name)
        if existing:
            if force_mode:
                # create a timestamped copy instead of skipping
                new_name = f"{name}-restored-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                if dry_run:
                    created_channels.append(f"{new_name} (would be created, original exists)")
                    continue
                try:
                    if ch_type == 'text':
                        new_ch = await ctx.guild.create_text_channel(name=new_name, category=category, overwrites=overwrites)
                    elif ch_type == 'voice':
                        new_ch = await ctx.guild.create_voice_channel(name=new_name, category=category, overwrites=overwrites)
                    else:
                        new_ch = await ctx.guild.create_text_channel(name=new_name, category=category, overwrites=overwrites)
                    created_channels.append(new_name)
                    # set channel attributes if available
                    update_kwargs = {}
                    if ch.get('position') is not None:
                        update_kwargs['position'] = ch.get('position')
                    if ch.get('topic') is not None:
                        update_kwargs['topic'] = ch.get('topic')
                    if ch.get('nsfw') is not None:
                        update_kwargs['nsfw'] = ch.get('nsfw')
                    if ch.get('rate_limit_per_user') is not None:
                        update_kwargs['rate_limit_per_user'] = ch.get('rate_limit_per_user')
                    if ch.get('bitrate') is not None:
                        update_kwargs['bitrate'] = ch.get('bitrate')
                    if ch.get('user_limit') is not None:
                        update_kwargs['user_limit'] = ch.get('user_limit')
                    if update_kwargs:
                        try:
                            await new_ch.edit(**update_kwargs)
                        except Exception as e:
                            print(f"Failed to set channel attributes for {new_name}: {e}")
                except Exception as e:
                    failed_channels.append(f"{name} (force create failed): {e}")
                continue
            skipped_channels.append(name)
            # if exists, optionally update overwrites and attributes
            if not dry_run:
                for role_name, perms in (ch.get('overwrites') or {}).items():
                    role_obj = discord.utils.get(ctx.guild.roles, name=role_name) if role_name != 'everyone' else ctx.guild.default_role
                    if role_obj:
                        try:
                            allow_v = perms.get('allow', 0)
                            deny_v = perms.get('deny', 0)
                            allow_p = discord.Permissions(value=allow_v)
                            deny_p = discord.Permissions(value=deny_v)
                            overwrite = discord.PermissionOverwrite.from_pair(allow_p, deny_p)
                            await existing.set_permissions(role_obj, overwrite=overwrite)
                        except Exception as e:
                            print(f"Failed to set overwrite on channel {name}: {e}")
                # update attributes
                update_kwargs = {}
                if ch.get('topic') is not None:
                    update_kwargs['topic'] = ch.get('topic')
                if ch.get('nsfw') is not None:
                    update_kwargs['nsfw'] = ch.get('nsfw')
                if ch.get('rate_limit_per_user') is not None:
                    update_kwargs['rate_limit_per_user'] = ch.get('rate_limit_per_user')
                if update_kwargs:
                    try:
                        await existing.edit(**update_kwargs)
                    except Exception as e:
                        print(f"Failed to update attributes on existing channel {name}: {e}")
            continue

        category = None
        if ch.get('category'):
            category = find_category(ctx.guild, ch.get('category'))

        # Build overwrites mapping
        overwrites = {}
        for role_name, perms in (ch.get('overwrites') or {}).items():
            role_obj = discord.utils.get(ctx.guild.roles, name=role_name) if role_name != 'everyone' else ctx.guild.default_role
            if role_obj:
                try:
                    allow_v = perms.get('allow', 0)
                    deny_v = perms.get('deny', 0)
                    allow_p = discord.Permissions(value=allow_v)
                    deny_p = discord.Permissions(value=deny_v)
                    overwrites[role_obj] = discord.PermissionOverwrite.from_pair(allow_p, deny_p)
                except Exception:
                    pass

        try:
            if dry_run:
                created_channels.append(name)
            else:
                if ch_type == 'text':
                    new_ch = await ctx.guild.create_text_channel(name=name, category=category, overwrites=overwrites)
                elif ch_type == 'voice':
                    new_ch = await ctx.guild.create_voice_channel(name=name, category=category, overwrites=overwrites)
                else:
                    new_ch = await ctx.guild.create_text_channel(name=name, category=category, overwrites=overwrites)
                created_channels.append(name)
                # set channel attributes if available
                update_kwargs = {}
                if ch.get('position') is not None:
                    update_kwargs['position'] = ch.get('position')
                if ch.get('topic') is not None:
                    update_kwargs['topic'] = ch.get('topic')
                if ch.get('nsfw') is not None:
                    update_kwargs['nsfw'] = ch.get('nsfw')
                if ch.get('rate_limit_per_user') is not None:
                    update_kwargs['rate_limit_per_user'] = ch.get('rate_limit_per_user')
                if ch.get('bitrate') is not None:
                    update_kwargs['bitrate'] = ch.get('bitrate')
                if ch.get('user_limit') is not None:
                    update_kwargs['user_limit'] = ch.get('user_limit')
                if update_kwargs:
                    try:
                        await new_ch.edit(**update_kwargs)
                    except Exception as e:
                        print(f"Failed to set channel attributes for {name}: {e}")
        except discord.Forbidden:
            failed_channels.append(f"{name} (Forbidden)")
            await ctx.send(f"❌ Missing permission to create channel '{name}'. Check my Manage Channels permission and role hierarchy.")
        except Exception as e:
            failed_channels.append(f"{name} ({e})")
            print(f"Error creating channel {name}: {e}")

    # Summarize
    lines = [f"Restore summary:", f"  Roles created/would create: {len(created_roles)}", f"  Roles skipped: {len(skipped_roles)}", f"  Role failures: {len(failed_roles)}", f"  Categories created/would create: {len(created_categories)}", f"  Categories skipped: {len(skipped_categories)}", f"  Category failures: {len(failed_categories)}", f"  Channels created/would create: {len(created_channels)}", f"  Channel skipped: {len(skipped_channels)}", f"  Channel failures: {len(failed_channels)}"]

    if dry_run:
        sample = "\n".join((created_roles[:50] or []) + (created_categories[:50] or []) + (created_channels[:50] or [])) or "No items would be created."
        await ctx.send(f"🔍 Dry run summary:\n{sample}")
    else:
        await ctx.send("\n".join(lines))


@bot.command(name='load_backup')
@commands.has_permissions(administrator=True)
@commands.bot_has_guild_permissions(manage_roles=True, manage_channels=True)
async def load_backup(ctx, filename: str, mode: str = ""):
    """Load and restore a server from a backup file. Use `dry` to preview."""
    if not ctx.guild:
        await ctx.send("This command only works in a server!")
        return

    filepath = f"{BACKUP_DIR}/{filename}"
    if not os.path.exists(filepath):
        await ctx.send(f"❌ Backup file not found: `{filename}`")
        return

    with open(filepath, 'r', encoding='utf-8') as f:
        backup_data = json.load(f)

    await ctx.send(f"📋 Loading backup from {backup_data.get('timestamp', 'unknown timestamp')}...")

    # Restore roles
    roles = backup_data.get('roles', [])
    created_roles = []
    skipped_roles = []
    failed_roles = []
    dry_run = (mode or "").lower() == "dry"

    for role_data in roles:
        name = role_data.get('name') or 'Unnamed'
        color_val = role_data.get('color', 0) or 0
        existing = discord.utils.get(ctx.guild.roles, name=name)
        if existing:
            skipped_roles.append(name)
            continue
        try:
            if dry_run:
                created_roles.append(name)
            else:
                await ctx.guild.create_role(name=name, color=discord.Color(color_val))
                created_roles.append(name)
        except discord.Forbidden:
            failed_roles.append(f"{name} (Forbidden)")
            await ctx.send(f"❌ Missing permission to create role '{name}'. Check my role position and Manage Roles permission.")
        except Exception as e:
            failed_roles.append(f"{name} ({e})")
            print(f"Error creating role {name}: {e}")

    # Restore categories and channels (same logic as restore_server)
    channels = backup_data.get('channels', [])
    created_categories = []
    created_channels = []
    skipped_channels = []
    failed_channels = []

    for ch in channels:
        if (ch.get('type') or '').lower() == 'category':
            name = ch.get('name')
            existing_cat = discord.utils.get(ctx.guild.categories, name=name)
            if existing_cat:
                skipped_channels.append(f"Category: {name}")
                continue
            try:
                if dry_run:
                    created_categories.append(name)
                else:
                    await ctx.guild.create_category(name=name)
                    created_categories.append(name)
            except Exception as e:
                failed_channels.append(f"Category: {name} ({e})")
                await ctx.send(f"⚠️ Failed to create category {name}: {e}")

    def find_category(guild, name):
        return discord.utils.get(guild.categories, name=name)

    for ch in channels:
        ch_type = (ch.get('type') or '').lower()
        if ch_type == 'category':
            continue
        name = ch.get('name')
        existing = discord.utils.get(ctx.guild.channels, name=name)
        if existing:
            skipped_channels.append(name)
            continue

        category = None
        if ch.get('category'):
            category = find_category(ctx.guild, ch.get('category'))

        overwrites = {}
        for role_name, perms in (ch.get('overwrites') or {}).items():
            role_obj = discord.utils.get(ctx.guild.roles, name=role_name)
            if role_obj:
                try:
                    overwrites[role_obj] = discord.PermissionOverwrite(view_channel=perms.get('view_channel'))
                except Exception:
                    pass

        everyone = ctx.guild.default_role
        if 'everyone' in (ch.get('overwrites') or {}):
            val = ch['overwrites']['everyone'].get('view_channel')
            overwrites[everyone] = discord.PermissionOverwrite(view_channel=val)

        try:
            if dry_run:
                created_channels.append(name)
            else:
                if ch_type == 'text':
                    await ctx.guild.create_text_channel(name=name, category=category, overwrites=overwrites)
                    created_channels.append(name)
                elif ch_type == 'voice':
                    await ctx.guild.create_voice_channel(name=name, category=category, overwrites=overwrites)
                    created_channels.append(name)
                else:
                    await ctx.guild.create_text_channel(name=name, category=category, overwrites=overwrites)
                    created_channels.append(name)
        except discord.Forbidden:
            failed_channels.append(f"{name} (Forbidden)")
            await ctx.send(f"❌ Missing permission to create channel '{name}'. Check my Manage Channels permission and role hierarchy.")
        except Exception as e:
            failed_channels.append(f"{name} ({e})")
            print(f"Error creating channel {name}: {e}")

    if dry_run:
        sample = "\n".join((created_roles[:50] or []) + (created_categories[:50] or []) + (created_channels[:50] or [])) or "No items would be created."
        await ctx.send(f"🔍 Dry run summary:\n{sample}")
    else:
        summary = [f"Backup load summary:", f"  Roles created: {len(created_roles)}", f"  Roles skipped: {len(skipped_roles)}", f"  Role failures: {len(failed_roles)}", f"  Categories created: {len(created_categories)}", f"  Channels created: {len(created_channels)}", f"  Channel skipped: {len(skipped_channels)}", f"  Channel failures: {len(failed_channels)}"]
        await ctx.send("\n".join(summary))


@bot.command(name='inspectbackup')
@commands.has_permissions(administrator=True)
async def inspect_backup(ctx, filename: str):
    """Inspect a backup file (roles/channels/messages counts) without restoring."""
    filepath = f"{BACKUP_DIR}/{filename}"
    if not os.path.exists(filepath):
        await ctx.send(f"❌ Backup file not found: `{filename}`")
        return

    with open(filepath, 'r') as f:
        backup_data = json.load(f)

    name = backup_data.get('name', 'unknown')
    ts = backup_data.get('timestamp', 'unknown')
    channels = backup_data.get('channels', [])
    roles = backup_data.get('roles', [])

    sample_channels = "\n".join([f"{c.get('name')} ({len(c.get('messages', []))} msgs)" for c in channels[:50]]) or "None"
    sample_roles = "\n".join([r.get('name', 'unnamed') for r in roles[:50]]) or "None"

    await ctx.send(f"**Backup:** {name} from {ts}\n**Channels ({len(channels)}):**\n{sample_channels}\n\n**Roles ({len(roles)}):**\n{sample_roles}")


PURGE_ALLOWED_ID = int(os.getenv('PURGE_ALLOWED_ID', '0'))

@bot.command(name='purge')
async def purge_all(ctx, confirm: str = ""):
    """Delete all channels in the guild. Only the user with `PURGE_ALLOWED_ID` may run this.

    Usage: `!purge` (shows warning) then `!purge confirm` to proceed.
    """
    if PURGE_ALLOWED_ID == 0:
        await ctx.send("❌ PURGE_ALLOWED_ID not set in environment. Set PURGE_ALLOWED_ID to your Discord user ID to enable this command.")
        return
    if ctx.author.id != PURGE_ALLOWED_ID:
        await ctx.send("❌ You are not authorized to run this command.")
        return
    if confirm.lower() != 'confirm':
        count = len(ctx.guild.channels)
        await ctx.send(f"⚠️ This will delete **{count}** channels. To proceed, run `!purge confirm`.")
        return

    await ctx.send("🗑️ Purging all channels now...")
    deleted = 0
    failed = []
    for ch in list(ctx.guild.channels):
        try:
            await ch.delete(reason=f"Purged by {ctx.author}")
            deleted += 1
        except Exception as e:
            failed.append(f"{ch.name}: {e}")
    await ctx.send(f"✅ Deleted {deleted} channels. Failed: {len(failed)}")
    if failed:
        await ctx.send("Failed to delete some channels. Check console for details.")

@bot.command(name='backups')
async def list_backups(ctx):
    """List all available backups"""
    files = os.listdir(BACKUP_DIR) if os.path.exists(BACKUP_DIR) else []
    if not files:
        await ctx.send("No backups found.")
        return
    
    backup_list = "\n".join(files)
    await ctx.send(f"**Available backups:**\n```{backup_list}```")

@bot.command()
@commands.has_permissions(administrator=True)
@commands.bot_has_guild_permissions(manage_channels=True)
async def lockserver(ctx, role: discord.Role = None, mode: str = ""):
    """Locks all channels and categories so only the Verify role can see them.

    Usage: `!lockserver` or `!lockserver @Role` or `!lockserver @Role dry` to preview only.
    """

    guild = ctx.guild
    # If a role is provided, use it and remember it for this guild
    if role:
        verify_role = role
        try:
            save_verify_role(guild.id, role.id)
            await ctx.send(f"✅ Saved verify role for this server: {role.name}")
        except Exception as e:
            print(f"Failed to save verify role for guild {guild.id}: {e}")
    else:
        stored_id = load_verify_role(guild.id)
        if stored_id:
            verify_role = guild.get_role(stored_id)
        else:
            verify_role = guild.get_role(VERIFY_ROLE_ID)

    if not verify_role:
        available = ", ".join(r.name for r in guild.roles)
        await ctx.send(f"❌ Verify role not found for this server. Pass a role as argument to set it, e.g. `!lockserver @Role`\nAvailable roles: {available}")
        print(f"Verify role not found for guild {guild.id} (tried stored id {stored_id if 'stored_id' in locals() else 'none'} and default {VERIFY_ROLE_ID}).")
        return

    everyone = guild.default_role
    dry_run = (mode or "").lower() == "dry"
    await ctx.send(f"🔒 Starting lockdown{' (dry run)' if dry_run else ''}. Only role '{verify_role.name}' will see channels.")

    changed = []

    # Categories
    for category in guild.categories:
        try:
            cur_every = category.overwrites_for(everyone)
            cur_verify = category.overwrites_for(verify_role)
            will_change = (cur_every.view_channel is not False) or (cur_verify.view_channel is not True)
            if will_change:
                changed.append(f"Category: {category.name}")
                if not dry_run:
                    await category.set_permissions(everyone, view_channel=False)
                    await category.set_permissions(verify_role, view_channel=True)
                    print(f"Locked category: {category.name}")
        except Exception as e:
            print(f"Failed to lock category {category.name}: {e}")
            await ctx.send(f"⚠️ Failed to lock category {category.name}: {e}")

    # Channels (including uncategorized)
    for channel in guild.channels:
        try:
            cur_every = channel.overwrites_for(everyone)
            cur_verify = channel.overwrites_for(verify_role)
            will_change = (cur_every.view_channel is not False) or (cur_verify.view_channel is not True)
            if will_change:
                changed.append(f"Channel: {channel.name}")
                if not dry_run:
                    await channel.set_permissions(everyone, view_channel=False)
                    await channel.set_permissions(verify_role, view_channel=True)
                    print(f"Locked channel: {channel.name}")
        except Exception as e:
            print(f"Failed to lock channel {channel.name}: {e}")
            await ctx.send(f"⚠️ Failed to lock channel {channel.name}: {e}")

    if dry_run:
        sample = "\n".join(changed[:50]) or "No changes required; everything already matches desired state."
        await ctx.send(f"🔍 Dry run summary ({len(changed)} items that would change):\n{sample}")
    else:
        await ctx.send("✅ Lockdown complete. @everyone can no longer see channels.")


@bot.command()
@commands.has_permissions(administrator=True)
@commands.bot_has_guild_permissions(manage_channels=True)
async def unlockserver(ctx, role: discord.Role = None, mode: str = ""):
    """Reverts the permission changes done by lockserver. Use `dry` to preview."""
    guild = ctx.guild
    # If a role is provided, use it and remember it for this guild
    if role:
        verify_role = role
        try:
            save_verify_role(guild.id, role.id)
            await ctx.send(f"✅ Saved verify role for this server: {role.name}")
        except Exception as e:
            print(f"Failed to save verify role for guild {guild.id}: {e}")
    else:
        stored_id = load_verify_role(guild.id)
        if stored_id:
            verify_role = guild.get_role(stored_id)
        else:
            verify_role = guild.get_role(VERIFY_ROLE_ID)

    if not verify_role:
        available = ", ".join(r.name for r in guild.roles)
        await ctx.send(f"❌ Verify role not found for this server. Pass a role as argument to set it, e.g. `!unlockserver @Role`\nAvailable roles: {available}")
        return

    everyone = guild.default_role
    dry_run = (mode or "").lower() == "dry"
    await ctx.send(f"🔓 Starting unlock{' (dry run)' if dry_run else ''}. Removing explicit view overrides for {verify_role.name} and @everyone.")

    changed = []

    for category in guild.categories:
        try:
            cur_every = category.overwrites_for(everyone)
            cur_verify = category.overwrites_for(verify_role)
            if (cur_every.view_channel is False) or (cur_verify.view_channel is True):
                changed.append(f"Category: {category.name}")
                if not dry_run:
                    await category.set_permissions(everyone, view_channel=None)
                    await category.set_permissions(verify_role, view_channel=None)
        except Exception as e:
            print(f"Failed to unlock category {category.name}: {e}")
            await ctx.send(f"⚠️ Failed to unlock category {category.name}: {e}")

    for channel in guild.channels:
        try:
            cur_every = channel.overwrites_for(everyone)
            cur_verify = channel.overwrites_for(verify_role)
            if (cur_every.view_channel is False) or (cur_verify.view_channel is True):
                changed.append(f"Channel: {channel.name}")
                if not dry_run:
                    await channel.set_permissions(everyone, view_channel=None)
                    await channel.set_permissions(verify_role, view_channel=None)
        except Exception as e:
            print(f"Failed to unlock channel {channel.name}: {e}")
            await ctx.send(f"⚠️ Failed to unlock channel {channel.name}: {e}")

    if dry_run:
        sample = "\n".join(changed[:50]) or "No changes required; nothing to revert."
        await ctx.send(f"🔍 Dry run summary ({len(changed)} items that would change):\n{sample}")
    else:
        await ctx.send(f"✅ Unlock complete. Reverted explicit view overrides ({len(changed)} items).")


@bot.command(name='setverify')
@commands.has_permissions(administrator=True)
async def setverify(ctx, role: discord.Role):
    """Set and save the verify role for this server. Usage: `!setverify @Role`"""
    try:
        save_verify_role(ctx.guild.id, role.id)
        await ctx.send(f"✅ Saved verify role for this server: {role.name} (ID: {role.id})")
    except Exception as e:
        print(f"Failed to set verify role for {ctx.guild.id}: {e}")
        await ctx.send(f"⚠️ Failed to save verify role: {e}")


@bot.command(name='getverify')
@commands.has_permissions(administrator=True)
async def getverify(ctx):
    """Show the currently saved verify role for this server."""
    stored_id = load_verify_role(ctx.guild.id)
    if stored_id:
        role = ctx.guild.get_role(stored_id)
        if role:
            await ctx.send(f"Current saved verify role is: {role.name} (ID: {role.id})")
        else:
            await ctx.send(f"Saved verify role ID {stored_id} not found in this guild. Use `!setverify @Role` to update.")
    else:
        await ctx.send("No verify role saved for this server. Use `!setverify @Role` to set one.")


@bot.command(name='clearverify')
@commands.has_permissions(administrator=True)
async def clearverify(ctx):
    """Clear the saved verify role for this server."""
    path = os.path.join(SERVER_DIR, f"{ctx.guild.id}.txt")
    try:
        if os.path.exists(path):
            os.remove(path)
            await ctx.send("✅ Cleared saved verify role for this server.")
        else:
            await ctx.send("No saved verify role to clear.")
    except Exception as e:
        print(f"Failed to clear verify role for {ctx.guild.id}: {e}")
        await ctx.send(f"⚠️ Failed to clear saved verify role: {e}")


async def _is_restart_allowed(ctx):
    """Check if the invoking user is allowed to perform owner-only actions (env BOT_OWNER_ID or application owner)."""
    try:
        if BOT_OWNER_ID and ctx.author.id == BOT_OWNER_ID:
            return True
        return await bot.is_owner(ctx.author)
    except Exception:
        return False


@bot.command(name='ban')
@commands.check(_is_restart_allowed)
async def ban(ctx, guild_id: int):
    """Add a guild ID to the banned list and leave the guild if present. Usage: `!ban <guild_id>` (owner-only)"""
    try:
        added = add_banned_server(guild_id)
        if not added:
            await ctx.send(f"⚠️ Guild ID {guild_id} is already in the banned list or operation failed.")
            return
        await ctx.send(f"✅ Added guild ID {guild_id} to the banned list.")
        # If bot is in that guild, immediately handle it (DM owner + leave)
        g = discord.utils.get(bot.guilds, id=guild_id)
        if g:
            await ctx.send(f"🔔 Found running in guild '{g.name}' ({g.id}) — leaving now.")
            try:
                await handle_banned_guild(g)
            except Exception as e:
                await ctx.send(f"⚠️ Failed to handle banned guild {guild_id}: {e}")
    except Exception as e:
        await ctx.send(f"⚠️ Failed to add banned guild: {e}")


@ban.error
async def ban_error(ctx, error):
    if isinstance(error, commands.CheckFailure):
        await ctx.send("❌ You are not authorized to manage the banned list.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("⚠️ Usage: `!ban <guild_id>`")
    else:
        raise error


@bot.command(name='unban')
@commands.check(_is_restart_allowed)
async def unban(ctx, guild_id: int):
    """Remove a guild ID from the banned list. Usage: `!unban <guild_id>` (owner-only)"""
    try:
        removed = remove_banned_server(guild_id)
        if removed:
            await ctx.send(f"✅ Removed guild ID {guild_id} from the banned list.")
        else:
            await ctx.send(f"⚠️ Guild ID {guild_id} not found in the banned list.")
    except Exception as e:
        await ctx.send(f"⚠️ Failed to remove banned guild: {e}")


@unban.error
async def unban_error(ctx, error):
    if isinstance(error, commands.CheckFailure):
        await ctx.send("❌ You are not authorized to manage the banned list.")
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send("⚠️ Usage: `!unban <guild_id>`")
    else:
        raise error


@bot.command()
@commands.has_permissions(administrator=True)
async def inspect(ctx, channel: discord.abc.GuildChannel = None):
    """Inspects permissions and overwrites for debugging. Defaults to current channel."""
    channel = channel or ctx.channel
    guild = ctx.guild
    me = guild.me

    # Bot guild perms
    bot_guild_perms = guild.me.guild_permissions
    bot_role_pos = max((r.position for r in guild.roles if r in me.roles), default=0)

    msg = [f"**Bot:** {me} (ID: {me.id})", f"**Guild perms:** {bot_guild_perms}", f"**Bot top role position:** {bot_role_pos}", ""]

    # Channel/category overwrites
    cat = channel.category
    if cat:
        msg.append(f"**Category '{cat.name}' overwrites:** {cat.overwrites}")
    msg.append(f"**Channel '{channel.name}' overwrites:** {channel.overwrites}")

    # Short role listing
    role_list = []
    for r in guild.roles:
        role_list.append(f"{r.name} (pos {r.position}, id {r.id})")
    msg.append("\n**Roles in guild:**\n" + ", ".join(role_list[:50]))

    await ctx.send("\n".join(msg))

@bot.command(name='resolve')
async def resolve(ctx, *, note: str = ""):
    """Announce that the message is being resolved by the bot and remove the command message from the user."""
    # Try to delete the invoking message (requires Manage Messages permission)
    try:
        await ctx.message.delete()
    except Exception:
        # If deletion fails, continue without raising
        pass

    description = (
        "⚙️ Please be advised that this message is currently being processed and resolved by the Fightgamer124.inc Discord Bot. "
        "Our automated system is actively handling the task to ensure a prompt and accurate resolution. "
        "Thank you for your patience while the bot completes this process."
    )

    embed = discord.Embed(
        title="Message Under Review",
        description=description,
        color=discord.Color.from_rgb(91, 32, 154),
        timestamp=datetime.now(ZoneInfo("Europe/Berlin"))
    )

    # Add requester info
    try:
        embed.set_author(name=str(ctx.author), icon_url=ctx.author.display_avatar.url)
    except Exception:
        embed.set_author(name=str(ctx.author))

    if note:
        # Limit note length to avoid oversized embeds
        note_value = note if len(note) <= 1024 else note[:1021] + "..."
        embed.add_field(name="Additional Notes", value=note_value, inline=False)

    embed.set_footer(text="Fightgamer124.inc Discord Bot • We will notify you when resolution is complete")

    await ctx.send(embed=embed)

@bot.command(name='restart')
@commands.check(_is_restart_allowed)
async def restart(ctx, confirm: str = ""):
    """Restart the bot process. Usage: `!restart confirm` (owner-only)."""
    if confirm.lower() != 'confirm':
        await ctx.send("⚠️ This will restart the bot. To proceed, run `!restart confirm`.")
        return

    await ctx.send(f"🔁 Restarting now... (requested by {ctx.author} - ID: {ctx.author.id})")

    # Stop background tasks (best-effort)
    try:
        change_status.stop()
    except Exception:
        pass
    try:
        poll_banned_file.stop()
    except Exception:
        pass

    # Close the bot connection and re-exec the process
    try:
        await bot.close()
    except Exception:
        pass

    try:
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        print(f"Failed to re-exec process for restart: {e}")
        sys.exit(0)


@restart.error
async def restart_error(ctx, error):
    if isinstance(error, commands.CheckFailure):
        await ctx.send("❌ You are not authorized to restart the bot.")
    else:
        # Re-raise unexpected errors so they are not silently ignored
        raise error
# DM contact handler: reply to `!contact` DMs with TOS/Privacy links and support email
@bot.event
async def on_message(message):
    """Handle direct messages to the bot. Supports `!contact` for policies and `!appeal <msg>` to forward appeals to the bot owner."""
    # ignore messages from bots (including ourselves)
    if message.author.bot:
        return

    # Only respond to DMs (no guild attached)
    if message.guild is None:
        content = message.content.strip()
        lower = content.lower()

        # Owner reply handling: allow the bot owner to reply to forwarded appeals (reply to the forwarded message)
        is_owner = False
        try:
            if BOT_OWNER_ID and message.author.id == BOT_OWNER_ID:
                is_owner = True
            else:
                is_owner = await bot.is_owner(message.author)
        except Exception:
            is_owner = False

        if is_owner and getattr(message, 'reference', None) and getattr(message.reference, 'message_id', None):
            ref_id = message.reference.message_id
            mapping = forward_map.get(ref_id)
            if mapping:
                appellant_id = mapping.get('appellant_id')
                guild_id = mapping.get('guild_id')
                try:
                    target = bot.get_user(appellant_id) or await bot.fetch_user(appellant_id)
                    forward_text = (
                        f"📣 Reply from the bot owner regarding your appeal:\n\n{message.content}\n\n"
                        f"--\nFrom: {message.author} (ID: {message.author.id})"
                    )
                    sent_to_appellant = await target.send(forward_text)
                    # Record mapping so replies from the appellant to this bot message are routed back to the owner
                    try:
                        forward_map[sent_to_appellant.id] = {
                            'owner_id': message.author.id,
                            'appellant_id': appellant_id,
                            'guild_id': guild_id,
                            'owner_message_id': message.id
                        }
                        # Index the latest forwarded id for quick lookup by appellant
                        try:
                            appellant_latest_forward[appellant_id] = sent_to_appellant.id
                        except Exception:
                            pass
                    except Exception:
                        pass
                    try:
                        await message.channel.send("✅ Your reply was forwarded to the appellant.")
                    except Exception:
                        pass
                except Exception as e:
                    try:
                        await message.channel.send(f"⚠️ Failed to forward reply: {e}")
                    except Exception:
                        pass

                # If owner included '!unban' in their reply, try to remove the server from the banned list
                if "!unban" in message.content.lower():
                    gid = guild_id
                    if not gid:
                        import re
                        m = re.search(r"\b\d{17,19}\b", message.content)
                        gid = int(m.group()) if m else None

                    if gid:
                        removed = remove_banned_server(gid)
                        if removed:
                            try:
                                await target.send(f"✅ Your server (ID: {gid}) has been unbanned. You may re-invite the bot now.")
                            except Exception:
                                pass
                            try:
                                await message.channel.send(f"✅ Server {gid} removed from the banned list and the appellant was notified.")
                            except Exception:
                                pass
                        else:
                            try:
                                await message.channel.send(f"⚠️ Server ID {gid} was not found in the banned list.")
                            except Exception:
                                pass
                    else:
                        try:
                            await message.channel.send("⚠️ No server ID found to unban. Include the server ID in your reply or in the original appeal.")
                        except Exception:
                            pass
                return

        # Forward any DM from an appellant to the owner even if not replying to a forwarded message
        if not is_owner:
            try:
                # find the most recent mapping for this appellant (if any)
                mapping = None
                for v in forward_map.values():
                    if v.get('appellant_id') == message.author.id and v.get('owner_id'):
                        mapping = v
                if mapping:
                    # use a clear name for the resolved owner for replies
                    Reply_owner = mapping.get('owner_id')
                    guild_id = mapping.get('guild_id')
                    try:
                        # Safety check: don't forward to the appellant themselves
                        if Reply_owner == message.author.id:
                            try:
                                print(f"[appeal] WARNING: Forward-owner resolved to appellant ({Reply_owner}) — using BOT_OWNER_ID fallback if available")
                            except Exception:
                                pass
                            if BOT_OWNER_ID and BOT_OWNER_ID != message.author.id:
                                Reply_owner = BOT_OWNER_ID

                        owner_user = bot.get_user(Reply_owner) or await bot.fetch_user(Reply_owner)
                        forwarded = await owner_user.send(
                            f"📣 Message from appellant {message.author} (ID: {message.author.id}):\n\n{message.content}\n\n--\n(Forwarded by bot)"
                        )
                        # Map this forwarded message so owner replies can be routed back
                        try:
                            forward_map[forwarded.id] = {
                                'owner_id': Reply_owner,
                                'appellant_id': message.author.id,
                                'guild_id': guild_id
                            }
                            try:
                                appellant_latest_forward[message.author.id] = forwarded.id
                            except Exception:
                                pass
                        except Exception:
                            pass
                        try:
                            await message.channel.send("✅ Your message was forwarded to the bot owner.")
                        except Exception:
                            pass
                    except Exception as e:
                        try:
                            await message.channel.send(f"⚠️ Failed to forward your message to the owner: {e}")
                        except Exception:
                            pass
                    return
            except Exception:
                pass

        # Appellant reply handling: if the appellant replies to a message we sent to them (owner's forwarded reply), forward it to the owner
        if getattr(message, 'reference', None) and getattr(message.reference, 'message_id', None):
            ref_id = message.reference.message_id
            mapping = forward_map.get(ref_id)

            # Fallback: if we didn't find a mapping by the referenced message id, try to find
            # the most recent mapping for this appellant (helps when mapping keys changed)
            if not mapping:
                try:
                    for v in reversed(list(forward_map.values())):
                        if v.get('appellant_id') == message.author.id and v.get('owner_id'):
                            mapping = v
                            break
                except Exception:
                    mapping = None

            if mapping and message.author.id == mapping.get('appellant_id'):
                # Use a clear variable name to hold the resolved owner for replies
                Reply_owner = mapping.get('owner_id')
                if not Reply_owner:
                    # try indexed latest forwarded id
                    try:
                        fid = appellant_latest_forward.get(message.author.id)
                        if fid:
                            Reply_owner = forward_map.get(fid, {}).get('owner_id')
                    except Exception:
                        pass
                if not Reply_owner:
                    # brute-force scan values for matching appellant entry
                    try:
                        for v in forward_map.values():
                            if v.get('appellant_id') == message.author.id and v.get('owner_id'):
                                Reply_owner = v.get('owner_id')
                                break
                    except Exception:
                        pass

                if Reply_owner:
                    try:
                        # Debug/logging to help diagnose missing deliveries
                        try:
                            print(f"[appeal] forwarding appellant reply msg={message.id} ref={ref_id} -> Reply_owner={Reply_owner}")
                            print(f"[appeal] forward_map_keys={list(forward_map.keys())}")
                            print(f"[appeal] appellant_latest_forward={appellant_latest_forward.get(message.author.id)}")
                        except Exception:
                            pass

                        # Safety: avoid sending to the appellant themselves (mapping corruption)
                        if Reply_owner == message.author.id:
                            try:
                                print(f"[appeal] WARNING: resolved Reply_owner == appellant ({Reply_owner}). Trying BOT_OWNER_ID fallback.")
                            except Exception:
                                pass
                            if BOT_OWNER_ID and BOT_OWNER_ID != message.author.id:
                                Reply_owner = BOT_OWNER_ID
                            else:
                                # try to find any other owner_id in forward_map values
                                try:
                                    for v in forward_map.values():
                                        if v.get('owner_id') and v.get('owner_id') != message.author.id:
                                            Reply_owner = v.get('owner_id')
                                            break
                                except Exception:
                                    pass

                        owner_user = bot.get_user(Reply_owner) or await bot.fetch_user(Reply_owner)
                        # Send the appellant's reply to the owner
                        forwarded = await owner_user.send(
                            f"📣 Reply from appellant {message.author} (ID: {message.author.id}):\n\n{message.content}\n\n--\n(Forwarded by bot)"
                        )

                        # Map this forwarded message so owner replies can be routed back
                        try:
                            forward_map[forwarded.id] = {
                                'owner_id': Reply_owner,
                                'appellant_id': message.author.id,
                                'guild_id': mapping.get('guild_id')
                            }
                            # update index
                            try:
                                appellant_latest_forward[message.author.id] = forwarded.id
                            except Exception:
                                pass
                        except Exception:
                            pass

                        try:
                            await message.channel.send("✅ Your reply was forwarded to the bot owner.")
                        except Exception:
                            pass
                    except Exception as e:
                        try:
                            await message.channel.send(f"⚠️ Failed to forward your reply to the owner: {e}")
                        except Exception:
                            pass
                else:
                    # final fallback: if BOT_OWNER_ID is configured, send to that user
                    if BOT_OWNER_ID:
                        try:
                            owner_user = bot.get_user(BOT_OWNER_ID) or await bot.fetch_user(BOT_OWNER_ID)
                            forwarded = await owner_user.send(
                                f"📣 Reply from appellant {message.author} (ID: {message.author.id}) (FALLBACK):\n\n{message.content}\n\n--\n(Forwarded by bot)"
                            )
                            try:
                                await message.channel.send("✅ Your reply was forwarded to the bot owner (fallback).")
                            except Exception:
                                pass
                        except Exception as e:
                            try:
                                await message.channel.send(f"⚠️ Failed to forward your reply to the owner: {e}")
                            except Exception:
                                pass
                    else:
                        try:
                            await message.channel.send("⚠️ No owner associated with this appeal.")
                        except Exception:
                            pass
                return

        # Handle appeals: `!appeal <message>`
        if lower.startswith("!appeal"):
            appeal_text = content[len("!appeal"):].strip()
            if not appeal_text:
                await message.channel.send("⚠️ Please include your appeal message after also add you're server `!appeal`. Example: `!appeal I was banned by mistake...`")
                return

            SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "spygaming1245@gmail.com")

            # Resolve owner user (env var BOT_OWNER_ID preferred, otherwise app owner)
            owner_user = None
            try:
                if BOT_OWNER_ID:
                    try:
                        owner_user = bot.get_user(BOT_OWNER_ID) or await bot.fetch_user(BOT_OWNER_ID)
                    except Exception as e:
                        print(f"Failed to fetch BOT_OWNER_ID {BOT_OWNER_ID}: {e}")
                        owner_user = None
                if owner_user is None:
                    try:
                        appinfo = await bot.application_info()
                        owner_user = appinfo.owner
                    except Exception as e:
                        print(f"Failed to get application owner: {e}")
                        owner_user = None
            except Exception as e:
                print(f"Error resolving bot owner: {e}")
                owner_user = None

            mention = f"<@{message.author.id}>"
            owner_msg = (
                f"📢 Appeal received\n\n"
                f"From: {message.author} (ID: {message.author.id})\n"
                f"Mention: {mention}\n\n"
                f"Message:\n{appeal_text}\n\n"
                f"Reply to this DM or email: {SUPPORT_EMAIL}"
            )

            if owner_user:
                try:
                    sent = await owner_user.send(owner_msg)
                    # Try to parse a guild id from the appeal text (17-19 digit snowflake), if present
                    import re
                    m = re.search(r"\b\d{17,19}\b", appeal_text)
                    gid = int(m.group()) if m else None
                    forward_map[sent.id] = {
                        'owner_id': owner_user.id,
                        'appellant_id': message.author.id,
                        'guild_id': gid,
                        'appeal_text': appeal_text
                    }
                except Exception as e:
                    print(f"Failed to DM owner {getattr(owner_user, 'id', 'unknown')}: {e}")
            else:
                print("No bot owner configured; appeal could not be forwarded.")

            await message.channel.send("✅ Your appeal has been forwarded to the bot owner. They will contact you via Discord or email.")
            return

        # Handle contact request
        if lower == "!contact" or lower.startswith("!contact "):
            # Use environment variables if provided, otherwise fallback to placeholders
            TOS_URL = os.getenv("TOS_URL", "https://docs.google.com/document/d/1g5dpNftX0vH3_GU8tdRrxnxjydU3bsiWxBqhDokQYZ4/edit?usp=sharing")
            PRIVACY_URL = os.getenv("PRIVACY_URL", "https://docs.google.com/document/d/1hRKUsW7Tru-WEsi0B7_VubMdLQl1HKjFUxPXQKG_TNA/edit?usp=sharing")
            SUPPORT_EMAIL = os.getenv("SUPPORT_EMAIL", "spygaming1245@gmail.com")
            try:
                embed = discord.Embed(title="Contact & Policies", color=discord.Color.blurple())
                embed.add_field(name="Terms of Service", value=f"[View TOS]({TOS_URL})", inline=False)
                embed.add_field(name="Privacy Policy", value=f"[View Privacy Policy]({PRIVACY_URL})", inline=False)
                embed.add_field(name="Support", value=f"Email: {SUPPORT_EMAIL}", inline=False)
                embed.set_footer(text="We'll respond as soon as we can; for urgent issues email support.")
                await message.channel.send(embed=embed)
            except Exception:
                # Fallback to plain text for clients that don't support embeds
                await message.channel.send(f"Terms of Service: {TOS_URL}\nPrivacy Policy: {PRIVACY_URL}\nSupport: {SUPPORT_EMAIL}")
            return
        
