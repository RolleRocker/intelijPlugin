package com.example.oauthplugin.statusbar;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.wm.StatusBar;
import com.intellij.openapi.wm.StatusBarWidget;
import com.intellij.util.Consumer;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.awt.event.MouseEvent;

public final class AuthStatusBarWidget implements StatusBarWidget, StatusBarWidget.TextPresentation {

    public static final String ID = "com.example.oauthplugin.AuthStatusBarWidget";

    private StatusBar statusBar;

    @Override
    public @NotNull String ID() {
        return ID;
    }

    @Override
    public void install(@NotNull StatusBar statusBar) {
        this.statusBar = statusBar;
    }

    @Override
    public void dispose() {
        statusBar = null;
    }

    @Override
    public WidgetPresentation getPresentation() {
        return this;
    }

    @Override
    public @NotNull String getText() {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        return authService.isLoggedIn() ? "Signed in" : "Not signed in";
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

    /** Call after login/logout completes so the widget text refreshes immediately. */
    public void refresh() {
        if (statusBar != null) {
            statusBar.updateWidget(ID);
        }
    }
}
