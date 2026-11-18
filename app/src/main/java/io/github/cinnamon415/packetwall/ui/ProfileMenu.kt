package io.github.cinnamon415.packetwall.ui

import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.res.stringResource
import io.github.cinnamon415.packetwall.PacketwallApp
import io.github.cinnamon415.packetwall.R

/** Switch the active profile from wherever it is shown (Home, Global rules). */
@Composable
fun ProfileMenu(app: PacketwallApp, expanded: Boolean, onDismiss: () -> Unit, onOpenSets: (() -> Unit)?) {
    val st by app.firewall.state.collectAsState()
    DropdownMenu(expanded, onDismiss) {
        st.profiles.forEach { p ->
            DropdownMenuItem(
                { Text(p.name) },
                {
                    app.firewall.activateProfile(p.id)
                    onDismiss()
                },
                leadingIcon = { RadioButton(st.activeProfile == p.id, null) }
            )
        }
        if (onOpenSets != null) {
            HorizontalDivider()
            DropdownMenuItem({ Text(stringResource(R.string.nav_sets)) }, {
                onDismiss()
                onOpenSets()
            })
        }
    }
}
