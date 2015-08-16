#include <pebble.h>
int hey;

void window_stack_push__patch(Window *window, bool animated) {
  hey = 1;
  window_stack_push(window, animated);
}
