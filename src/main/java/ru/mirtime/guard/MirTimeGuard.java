package ru.mirtime.guard;

import com.google.inject.Inject;
import com.velocitypowered.api.command.CommandSource;
import com.velocitypowered.api.command.SimpleCommand;
import com.velocitypowered.api.event.PostOrder;
import com.velocitypowered.api.event.Subscribe;
import com.velocitypowered.api.event.command.CommandExecuteEvent;
import com.velocitypowered.api.event.connection.PostLoginEvent;
import com.velocitypowered.api.event.connection.PreLoginEvent;
import com.velocitypowered.api.event.proxy.ProxyInitializeEvent;
import com.velocitypowered.api.plugin.Plugin;
import com.velocitypowered.api.plugin.annotation.DataDirectory;
import com.velocitypowered.api.proxy.Player;
import com.velocitypowered.api.proxy.ProxyServer;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.slf4j.Logger;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Plugin(
        id = "mirtimeguard",
        name = "MirTimeGuard",
        version = "1.0.0",
        authors = {"Mir-Time"}
)
public class MirTimeGuard implements SimpleCommand {

    private final ProxyServer server;
    private final Logger logger;
    private final Path dataDir;

    private final Set<String> verifiedIps = ConcurrentHashMap.newKeySet();
    private final Set<String> adminNames = ConcurrentHashMap.newKeySet();
    private final Map<String, List<Long>> ipAttempts = new ConcurrentHashMap<>();

    private final AtomicInteger connectionsThisSec = new AtomicInteger(0);
    private final AtomicLong attackModeUntil = new AtomicLong(0);
    private final AtomicLong blockedBotsTotal = new AtomicLong(0);
    private boolean manualAttackMode = false;

    private int maxConnPerIp = 4;
    private int attackThreshold = 12;
    private int attackDurationSec = 60;
    private boolean blockProxyCmds = true;

    @Inject
    public MirTimeGuard(ProxyServer server, Logger logger, @DataDirectory Path dataDir) {
        this.server = server;
        this.logger = logger;
        this.dataDir = dataDir;
    }

    @Subscribe
    public void onProxyInit(ProxyInitializeEvent e) {
        loadConfigs();
        server.getCommandManager().register(
                server.getCommandManager().metaBuilder("mtguard").aliases("mtg", "antibot").build(),
                this
        );

        server.getScheduler().buildTask(this, () -> {
            int cps = connectionsThisSec.getAndSet(0);
            if (cps >= attackThreshold && !isAttackMode()) {
                for (Player online : server.getAllPlayers()) {
                    if (online.getRemoteAddress() != null && online.getRemoteAddress().getAddress() != null) {
                        verifiedIps.add(online.getRemoteAddress().getAddress().getHostAddress());
                    }
                }
                saveVerified();
                attackModeUntil.set(System.currentTimeMillis() + attackDurationSec * 1000L);
                logger.warn("[MirTimeGuard] Обнаружена атака ({} входов/сек)! Включён РЕЖИМ ОСАДЫ на {} сек. Новые IP заблокированы.", cps, attackDurationSec);
            }
        }).repeat(1, TimeUnit.SECONDS).schedule();

        logger.info("MirTimeGuard v1.0.0 (Авто-защита Velocity от бот-атак) запущен! В базе проверенных IP: {}", verifiedIps.size());
    }

    public boolean isAttackMode() {
        return manualAttackMode || System.currentTimeMillis() < attackModeUntil.get();
    }

    private boolean isAdmin(CommandSource src) {
        if (src.hasPermission("mirtime.guard.admin")) return true;
        if (src instanceof Player p) {
            return adminNames.contains(p.getUsername().toLowerCase());
        }
        return !(src instanceof Player);
    }

    @Subscribe(order = PostOrder.FIRST)
    public void onPreLogin(PreLoginEvent e) {
        String ip = (e.getConnection().getRemoteAddress() != null && e.getConnection().getRemoteAddress().getAddress() != null)
                ? e.getConnection().getRemoteAddress().getAddress().getHostAddress()
                : "unknown";
        if (ip.equals("unknown") || ip.equals("127.0.0.1")) return;

        long now = System.currentTimeMillis();
        connectionsThisSec.incrementAndGet();

        List<Long> list = ipAttempts.computeIfAbsent(ip, k -> Collections.synchronizedList(new ArrayList<>()));
        synchronized (list) {
            list.removeIf(t -> (now - t) > 10_000L);
            if (list.size() >= maxConnPerIp) {
                blockedBotsTotal.incrementAndGet();
                e.setResult(PreLoginEvent.PreLoginComponentResult.denied(color(
                        "&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lMIR-TIME GUARD &8» &cСлишком частые подключения!\n\n" +
                        "&fПодождите &x&0&0&f&f&6&610 секунд &fперед повторным входом."
                )));
                return;
            }
            list.add(now);
        }

        if (isAttackMode() && !verifiedIps.contains(ip)) {
            blockedBotsTotal.incrementAndGet();
            e.setResult(PreLoginEvent.PreLoginComponentResult.denied(color(
                    "&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lMIR-TIME GUARD &8» &cВход временно ограничен!\n\n" +
                    "&fСервер отражает бот-атаку (&x&0&0&e&5&f&fРежим Осады&f).\n" +
                    "&fСейчас пускает только игроков, которые уже были на сервере.\n\n" +
                    "&7Попробуйте зайти через 1–2 минуты."
            )));
        }
    }

    @Subscribe
    public void onPostLogin(PostLoginEvent e) {
        if (!isAttackMode()) {
            Player p = e.getPlayer();
            if (p.getRemoteAddress() != null && p.getRemoteAddress().getAddress() != null) {
                String ip = p.getRemoteAddress().getAddress().getHostAddress();
                if (verifiedIps.add(ip)) {
                    saveVerified();
                }
            }
        }
    }
    @Subscribe
    public void onProxyCommand(CommandExecuteEvent e) {
        if (!blockProxyCmds) return;
        if (!(e.getCommandSource() instanceof Player p)) return;
        if (isAdmin(p)) return;

        String raw = e.getCommand().toLowerCase().trim();
        int sp = raw.indexOf(' ');
        String cmd = (sp == -1) ? raw : raw.substring(0, sp);

        if (cmd.equals("velocity") || cmd.equals("vplugins") || cmd.equals("glist") || cmd.equals("server")) {
            e.setResult(CommandExecuteEvent.CommandResult.denied());
            p.sendMessage(color("&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lMIR-TIME &8» &cНеизвестная или недоступная команда!"));
        }
    }

    @Override
    public void execute(Invocation invocation) {
        CommandSource src = invocation.source();
        List<String> args = Arrays.asList(invocation.arguments());

        if (!isAdmin(src)) {
            src.sendMessage(color("&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lMIR-TIME GUARD &8» &cУ вас нет прав!"));
            return;
        }

        if (args.isEmpty() || args.get(0).equalsIgnoreCase("stats")) {
            src.sendMessage(color("&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lСТАТИСТИКА MIR-TIME GUARD:"));
            src.sendMessage(color(" &8▪ &fРежим осады: " + (isAttackMode() ? "&c&lВКЛЮЧЁН" : "&x&0&0&f&f&6&6выключен")));
            src.sendMessage(color(" &8▪ &fПроверенных IP в базе: &x&0&0&e&5&f&f" + verifiedIps.size()));
            src.sendMessage(color(" &8▪ &fОтбито бот-подключений: &x&0&0&f&f&6&6" + blockedBotsTotal.get()));
            return;
        }

        String sub = args.get(0).toLowerCase();
        if (sub.equals("reload")) {
            loadConfigs();
            src.sendMessage(color("&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lMIR-TIME GUARD &8» &x&0&0&f&f&6&6Конфигурация перезагружена!"));
        } else if (sub.equals("attack") && args.size() >= 2) {
            manualAttackMode = args.get(1).equalsIgnoreCase("on");
            if (manualAttackMode) {
                for (Player online : server.getAllPlayers()) {
                    if (online.getRemoteAddress() != null && online.getRemoteAddress().getAddress() != null) {
                        verifiedIps.add(online.getRemoteAddress().getAddress().getHostAddress());
                    }
                }
                saveVerified();
            } else {
                attackModeUntil.set(0);
            }
            src.sendMessage(color("&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lMIR-TIME GUARD &8» &fРежим осады вручную: " + (manualAttackMode ? "&c&lВКЛ" : "&x&0&0&f&f&6&6ВЫКЛ")));
        } else if (sub.equals("verify") && args.size() >= 2) {
            String target = args.get(1);
            Optional<Player> online = server.getPlayer(target);
            String ipToAdd = online.map(p -> p.getRemoteAddress().getAddress().getHostAddress()).orElse(target);
            verifiedIps.add(ipToAdd);
            saveVerified();
            src.sendMessage(color("&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lMIR-TIME GUARD &8» &x&0&0&f&f&6&6Адрес &f" + ipToAdd + " &x&0&0&f&f&6&6добавлен в белый список!"));
        } else {
            src.sendMessage(color("&x&0&0&5&5&f&f&l⚡ &x&0&0&e&5&f&f&lMIR-TIME GUARD &8» &fКоманды: &x&0&0&f&f&6&6/mtguard stats | attack <on|off> | verify <ник/ip> | reload"));
        }
    }

    @SuppressWarnings("unchecked")
    private void loadConfigs() {
        try {
            if (!Files.exists(dataDir)) Files.createDirectories(dataDir);
            Path cfgPath = dataDir.resolve("config.yml");
            if (!Files.exists(cfgPath)) {
                try (InputStream in = getClass().getResourceAsStream("/config.yml")) {
                    if (in != null) Files.copy(in, cfgPath);
                }
            }
            Yaml yaml = new Yaml();
            adminNames.clear();
            adminNames.add("ars3nbar");
            try (InputStream in = Files.newInputStream(cfgPath)) {
                Map<String, Object> root = yaml.load(in);
                if (root != null && root.get("settings") instanceof Map<?, ?> s) {
                    maxConnPerIp = getInt(s, "max-connections-per-ip", 4);
                    attackThreshold = getInt(s, "attack-mode-threshold-per-sec", 12);
                    attackDurationSec = getInt(s, "attack-mode-duration-seconds", 60);
                    blockProxyCmds = getBool(s, "block-proxy-commands", true);
                    if (s.get("admins") instanceof List<?> admList) {
                        for (Object a : admList) adminNames.add(String.valueOf(a).toLowerCase());
                    }
                }
            }

            Path verPath = dataDir.resolve("verified.yml");
            if (Files.exists(verPath)) {
                try (InputStream in = Files.newInputStream(verPath)) {
                    Map<String, Object> vRoot = yaml.load(in);
                    if (vRoot != null && vRoot.get("verified-ips") instanceof List<?> ips) {
                        verifiedIps.clear();
                        for (Object o : ips) verifiedIps.add(String.valueOf(o));
                    }
                }
            }
        } catch (Exception ex) {
            logger.error("Ошибка загрузки конфигов MirTimeGuard", ex);
        }
    }

    private void saveVerified() {
        try {
            if (!Files.exists(dataDir)) Files.createDirectories(dataDir);
            Path verPath = dataDir.resolve("verified.yml");
            DumperOptions opts = new DumperOptions();
            opts.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
            Yaml yaml = new Yaml(opts);
            Map<String, Object> data = new LinkedHashMap<>();
            data.put("verified-ips", new ArrayList<>(verifiedIps));
            try (Writer w = Files.newBufferedWriter(verPath, StandardCharsets.UTF_8)) {
                yaml.dump(data, w);
            }
        } catch (Exception ex) {
            logger.error("Ошибка сохранения verified.yml", ex);
        }
    }

    private int getInt(Map<?, ?> m, String k, int def) {
        Object v = m.get(k);
        return (v instanceof Number n) ? n.intValue() : def;
    }

    private boolean getBool(Map<?, ?> m, String k, boolean def) {
        Object v = m.get(k);
        return (v instanceof Boolean b) ? b : def;
    }

    private Component color(String s) {
        return LegacyComponentSerializer.legacyAmpersand().deserialize(s);
    }
}
