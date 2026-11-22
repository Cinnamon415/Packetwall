package io.github.cinnamon415.packetwall.ui

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.animation.scaleOut
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectVerticalDragGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxScope
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.FloatingActionButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SmallFloatingActionButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.snapshotFlow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.IntOffset
import androidx.compose.ui.unit.dp
import io.github.cinnamon415.packetwall.R
import kotlin.math.roundToInt
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/**
 * Where a lazy list is, estimated from the visible rows (rows of a log are about the same height):
 * [position] 0…1 from top to bottom, [visible] the part of the content on screen, [remaining] pixels
 * below the viewport.
 */
data class ListScroll(val position: Float, val visible: Float, val remaining: Float, val content: Float, val viewport: Float)

fun LazyListState.scrollEstimate(): ListScroll? {
    val info = layoutInfo
    val rows = info.visibleItemsInfo
    if (rows.isEmpty() || info.totalItemsCount == 0) return null
    val avg = rows.sumOf { it.size }.toFloat() / rows.size
    val viewport = (info.viewportEndOffset - info.viewportStartOffset).toFloat()
    val content = avg * info.totalItemsCount
    val scrolled = firstVisibleItemIndex * avg + firstVisibleItemScrollOffset
    val range = (content - viewport).coerceAtLeast(1f)
    return ListScroll(
        position = (scrolled / range).coerceIn(0f, 1f),
        visible = (viewport / content).coerceIn(0f, 1f),
        remaining = (content - viewport - scrolled).coerceAtLeast(0f),
        content = content,
        viewport = viewport
    )
}

/** Scrolls so that [position] (0…1) of the estimated content is at the top of the viewport. */
suspend fun LazyListState.scrollToFraction(position: Float) {
    val s = scrollEstimate() ?: return
    val rows = layoutInfo.visibleItemsInfo
    val avg = rows.sumOf { it.size }.toFloat() / rows.size
    val target = position.coerceIn(0f, 1f) * (s.content - s.viewport).coerceAtLeast(0f)
    val index = (target / avg).toInt().coerceIn(0, layoutInfo.totalItemsCount - 1)
    scrollToItem(index, (target - index * avg).roundToInt())
}

/**
 * Small "to the bottom" button: appears while the list is scrolled, hides 3 s after scrolling stops
 * or once the bottom is within half a screen. Sits at the bottom end of the enclosing [Box].
 */
@Composable
fun BoxScope.JumpToEndButton(state: LazyListState, label: String, modifier: Modifier = Modifier) {
    var active by remember { mutableStateOf(false) }
    LaunchedEffect(state) {
        snapshotFlow { state.isScrollInProgress }.collect { scrolling ->
            if (scrolling) {
                active = true
            } else {
                delay(3000)
                active = false
            }
        }
    }
    val far by remember(state) { derivedStateOf { state.scrollEstimate()?.let { it.remaining > it.viewport / 2 } ?: false } }
    val scope = rememberCoroutineScope()
    AnimatedVisibility(
        active && far,
        modifier.align(Alignment.BottomEnd).padding(end = 22.dp, bottom = 16.dp),
        enter = fadeIn(tween(180)) + scaleIn(tween(180), initialScale = 0.6f),
        exit = fadeOut(tween(180)) + scaleOut(tween(180), targetScale = 0.6f)
    ) {
        SmallFloatingActionButton(
            onClick = { scope.launch { state.animateScrollToItem((state.layoutInfo.totalItemsCount - 1).coerceAtLeast(0)) } },
            containerColor = MaterialTheme.colorScheme.secondaryContainer,
            contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
            elevation = FloatingActionButtonDefaults.elevation(3.dp, 3.dp, 4.dp, 4.dp)
        ) {
            Icon(painterResource(R.drawable.ic_arrow_down), label)
        }
    }
}

/**
 * Scrollbar that fades in while the list scrolls and out 1.5 s later. While visible it can be
 * dragged; during a drag it widens and a bubble shows [label] of the row in the middle of the screen
 * (the time of that connection). Fills the enclosing [Box] on its end side.
 */
@Composable
fun BoxScope.DragScrollbar(state: LazyListState, label: (index: Int) -> Pair<String, String>?) {
    var shown by remember { mutableStateOf(false) }
    var dragging by remember { mutableStateOf(false) }
    var dragPos by remember { mutableFloatStateOf(0f) }
    LaunchedEffect(state) {
        snapshotFlow { state.isScrollInProgress }.collect { scrolling ->
            if (scrolling) shown = true
        }
    }
    LaunchedEffect(shown, dragging, state.isScrollInProgress) {
        if (shown && !dragging && !state.isScrollInProgress) {
            delay(1500)
            shown = false
        }
    }
    LaunchedEffect(dragPos, dragging) { if (dragging) state.scrollToFraction(dragPos) }
    val est by remember(state) { derivedStateOf { state.scrollEstimate() } }
    val s = est ?: return
    if (s.visible >= 1f) return
    val alpha by animateFloatAsState(if (shown || dragging) 1f else 0f, tween(300), label = "bar")
    val width by animateDpAsState(if (dragging) 10.dp else 6.dp, tween(120), label = "thumb")
    val density = LocalDensity.current
    BoxWithConstraints(
        Modifier.matchParentSize().padding(vertical = 3.dp).alpha(alpha)
    ) {
        val trackPx = constraints.maxHeight.toFloat()
        val thumbPx = maxOf(with(density) { 36.dp.toPx() }, s.visible * trackPx).coerceAtMost(trackPx)
        val pos = if (dragging) dragPos else s.position
        val topPx = pos * (trackPx - thumbPx)
        Box(
            Modifier
                .align(Alignment.TopEnd)
                .offset { IntOffset(0, topPx.roundToInt()) }
                .size(22.dp, with(density) { thumbPx.toDp() })
                .then(
                    if (shown || dragging) {
                        Modifier.pointerInput(trackPx, thumbPx) {
                            var start = 0f
                            var moved = 0f
                            detectVerticalDragGestures(
                                onDragStart = {
                                    start = state.scrollEstimate()?.position ?: 0f
                                    moved = 0f
                                    dragPos = start
                                    dragging = true
                                },
                                onDragEnd = { dragging = false },
                                onDragCancel = { dragging = false }
                            ) { change, dy ->
                                change.consume()
                                moved += dy
                                dragPos = (start + moved / (trackPx - thumbPx).coerceAtLeast(1f)).coerceIn(0f, 1f)
                            }
                        }
                    } else {
                        Modifier
                    }
                )
        ) {
            Box(
                Modifier
                    .align(Alignment.CenterEnd)
                    .padding(end = 3.dp)
                    .width(width)
                    .fillMaxHeight()
                    .alpha(if (dragging) 1f else 0.75f)
                    .background(MaterialTheme.colorScheme.primary, RoundedCornerShape(5.dp))
            )
        }
        if (dragging) {
            val mid = state.layoutInfo.let { info ->
                val center = (info.viewportStartOffset + info.viewportEndOffset) / 2
                info.visibleItemsInfo.firstOrNull { center >= it.offset && center < it.offset + it.size }?.index
                    ?: state.firstVisibleItemIndex
            }
            label(mid)?.let { (time, day) ->
                var bubbleH by remember { mutableIntStateOf(0) }
                Surface(
                    shape = RoundedCornerShape(16.dp, 16.dp, 4.dp, 16.dp),
                    color = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary,
                    shadowElevation = 3.dp,
                    modifier = Modifier
                        .align(Alignment.TopEnd)
                        .padding(end = 30.dp)
                        .offset { IntOffset(0, (topPx + thumbPx / 2 - bubbleH / 2).roundToInt()) }
                        .onSizeChanged { bubbleH = it.height }
                ) {
                    Column(Modifier.padding(horizontal = 11.dp, vertical = 6.dp)) {
                        Text(time, style = MaterialTheme.typography.titleSmall, textAlign = TextAlign.End)
                        Text(day, style = MaterialTheme.typography.labelSmall, modifier = Modifier.alpha(0.85f))
                    }
                }
            }
        }
    }
}
