package com.example.oauthplugin.settings;

import com.example.oauthplugin.auth.AuthService;
import com.example.oauthplugin.statusbar.AuthStatusBarWidget;
import com.example.oauthplugin.actions.LoginProgress;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.util.ui.FormBuilder;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import java.util.concurrent.CompletableFuture;

/** Swing panel shown on the OAuth Sample Plugin settings page. */
public final class OAuthSettingsComponent {

    private final JPanel panel;
    private final JLabel statusLabel = new JLabel("Checking sign-in state...");
    private final JButton actionButton = new JButton();

    public OAuthSettingsComponent() {
        actionButton.setEnabled(false);
        actionButton.addActionListener(e -> {
            actionButton.setEnabled(false);
            AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);

            // isLoggedIn() performs PasswordSafe I/O, so decide the branch off the EDT.
            ApplicationManager.getApplication().executeOnPooledThread(() -> {
                if (authService.isLoggedIn()) {
                    authService.logout().whenComplete((result, throwable) -> onAuthActionComplete());
                } else {
                    CompletableFuture<Void> loginFuture = authService.login();
                    LoginProgress.show(null, authService, loginFuture);
                    loginFuture.whenComplete((result, throwable) -> onAuthActionComplete());
                }
            });
        });

        panel = FormBuilder.createFormBuilder()
                .addComponent(statusLabel)
                .addComponent(actionButton)
                .addComponentFillVertically(new JPanel(), 0)
                .getPanel();

        refresh();
    }

    public JPanel getPanel() {
        return panel;
    }

    /** Recomputes login state off the EDT, then updates the panel on the EDT. */
    public void refresh() {
        ApplicationManager.getApplication().executeOnPooledThread(() -> {
            AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
            boolean loggedIn = authService.isLoggedIn();

            ApplicationManager.getApplication().invokeLater(() -> {
                statusLabel.setText(loggedIn ? "Signed in" : "Not signed in");
                actionButton.setText(loggedIn ? "Sign Out" : "Sign In...");
                actionButton.setEnabled(true);
            });
        });
    }

    private void onAuthActionComplete() {
        ApplicationManager.getApplication().invokeLater(() -> {
            refresh();
            AuthStatusBarWidget.refreshAll();
        });
    }
}
