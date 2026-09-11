package com.example.oauthplugin.statusbar;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.wm.StatusBar;
import com.intellij.openapi.wm.StatusBarWidget;
import com.intellij.util.Consumer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.awt.event.MouseEvent;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

public final class AuthStatusBarWidget implements StatusBarWidget, StatusBarWidget.TextPresentation {

    public static final String ID = "com.example.oauthplugin.AuthStatusBarWidget";

    private static final Set<AuthStatusBarWidget> ACTIVE_WIDGETS =
            Collections.newSetFromMap(new ConcurrentHashMap<>());

    // Updated off the EDT in refreshState(); getText() only ever reads this
    // cached value so the platform can call it cheaply/synchronously.
    private volatile String cachedText = "Not signed in";

    private StatusBar statusBar;

    @Override
    public @NotNull String ID() {
        return ID;
    }

    @Override
    public void install(@NotNull StatusBar statusBar) {
        this.statusBar = statusBar;
        ACTIVE_WIDGETS.add(this);
        refreshState();
    }

    @Override
    public void dispose() {
        ACTIVE_WIDGETS.remove(this);
        statusBar = null;
    }

    @Override
    public WidgetPresentation getPresentation() {
        return this;
    }

    @Override
    public @NotNull String getText() {
        return cachedText;
    }

    @Override
    public float getAlignment() {
        return 0f;
    }

    @Override
    public @Nullable String getTooltipText() {
        return "OAuth Sample Plugin login state";
    }

    @Override
    public @Nullable Consumer<MouseEvent> getClickConsumer() {
        return null;
    }

    /** Recomputes login state off the EDT, then asks the status bar to repaint. */
    private void refreshState() {
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
            cachedText = authService.isLoggedIn() ? "Signed in" : "Not signed in";

            StatusBar bar = statusBar;
            if (bar != null) {
                ApplicationManager.getApplication().invokeLater(() -> bar.updateWidget(ID));
            }
        });
    }

    /**
     * Call after any login/logout state change so every open project's
     * widget picks up the new state. Safe to call from the EDT.
     */
    public static void refreshAll() {
        for (AuthStatusBarWidget widget : ACTIVE_WIDGETS) {
            widget.refreshState();
        }
    }
}
