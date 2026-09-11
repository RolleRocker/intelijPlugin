package com.example.oauthplugin.actions;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.ActionUpdateThread;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.application.ApplicationManager;
import org.jetbrains.annotations.NotNull;

public final class LogoutAction extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        authService.logout();

        NotificationGroupManager.getInstance()
                .getNotificationGroup("OAuth Sample Plugin")
                .createNotification("Signed out", NotificationType.INFORMATION)
                .notify(e.getProject());
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        e.getPresentation().setEnabled(authService.isLoggedIn());
    }

    @Override
    public @NotNull ActionUpdateThread getActionUpdateThread() {
        return ActionUpdateThread.BGT;
    }
}
