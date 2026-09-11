package com.example.oauthplugin.settings;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.util.ui.FormBuilder;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;

/** Swing panel shown on the OAuth Sample Plugin settings page. */
public final class OAuthSettingsComponent {

    private final JPanel panel;
    private final JLabel statusLabel = new JLabel();
    private final JButton actionButton = new JButton();

    public OAuthSettingsComponent() {
        actionButton.addActionListener(e -> {
            AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
            if (authService.isLoggedIn()) {
                authService.logout();
                refresh();
            } else {
                actionButton.setEnabled(false);
                authService.login().whenComplete((result, throwable) ->
                        ApplicationManager.getApplication().invokeLater(this::refresh));
            }
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

    public void refresh() {
        AuthService authService = ApplicationManager.getApplication().getService(AuthService.class);
        boolean loggedIn = authService.isLoggedIn();
        statusLabel.setText(loggedIn ? "Signed in" : "Not signed in");
        actionButton.setText(loggedIn ? "Sign Out" : "Sign In...");
        actionButton.setEnabled(true);
    }
}
