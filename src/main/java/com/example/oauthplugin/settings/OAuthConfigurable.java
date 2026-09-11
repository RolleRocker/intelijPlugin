package com.example.oauthplugin.settings;

import com.intellij.openapi.options.Configurable;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.JComponent;

public final class OAuthConfigurable implements Configurable {

    private OAuthSettingsComponent component;

    @Nls(capitalization = Nls.Capitalization.Title)
    @Override
    public String getDisplayName() {
        return "OAuth Sample Plugin";
    }

    @Override
    public @Nullable JComponent createComponent() {
        component = new OAuthSettingsComponent();
        return component.getPanel();
    }

    @Override
    public boolean isModified() {
        // Purely a login-state viewer/actuator; nothing to persist as settings.
        return false;
    }

    @Override
    public void apply() {
        // No persisted settings fields to apply.
    }

    @Override
    public void reset() {
        if (component != null) {
            component.refresh();
        }
    }

    @Override
    public void disposeUIResources() {
        component = null;
    }
}
