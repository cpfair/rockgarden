#include <pebble.h>

void window_stack_push__patch(Window *window, bool animated) {
  light_enable(true);
  window_stack_push(window, animated);
}
