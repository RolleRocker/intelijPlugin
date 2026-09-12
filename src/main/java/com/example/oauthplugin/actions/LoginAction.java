package com.example.oauthplugin.actions;

import com.example.oauthplugin.auth.AuthService;
import com.example.oauthplugin.statusbar.AuthStatusBarWidget;
import com.intellij.notification.NotificationGroupManager;
import com.intellij.notification.NotificationType;
import com.intellij.openapi.actionSystem.ActionUpdateThread;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.application.ApplicationManager;
import org.jetbrains.annotations.NotNull;

import java.util.concurrent.CompletableFuture;

public final class LoginAction extends AnAction {

    @Override
    public void actionPerformed(@NotNull AnActionEvent e) {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);

        CompletableFuture<Void> loginFuture = authService.login();
        LoginProgress.show(e.getProject(), authService, loginFuture);

        loginFuture.whenComplete((result, throwable) ->
                ApplicationManager.getApplication().invokeLater(() -> {
                    NotificationGroupManager notifications = NotificationGroupManager.getInstance();
                    if (throwable != null) {
                        notifications.getNotificationGroup("OAuth Sample Plugin")
                                .createNotification("Sign-in failed", throwable.getMessage(), NotificationType.ERROR)
                                .notify(e.getProject());
                    } else {
                        notifications.getNotificationGroup("OAuth Sample Plugin")
                                .createNotification("Signed in successfully", NotificationType.INFORMATION)
                                .notify(e.getProject());
                    }
                    AuthStatusBarWidget.refreshAll();
                }));
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        e.getPresentation().setEnabled(!authService.isLoggedIn());
    }

    @Override
    public @NotNull ActionUpdateThread getActionUpdateThread() {
        return ActionUpdateThread.BGT;
    }
}
