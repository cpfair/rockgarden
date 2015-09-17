Rock Garden
===========

Lets you patch Pebble apps. You can override C syscalls, add new Javascript, and, well, that's pretty much it. Oh, you can change the UUID, too.

Requirement
-----------

* Pebble SDK 3.x

Install
-------

    pip install git+https://github.com/cpfair/rockgarden.git

Usage
-----

    from rockgarden import Patcher

    ...

    Patcher().patch_pbw("the-app.pbw",
                        "the-app.patched.pbw",
                        c_sources=["my-patches.c"],
                        cflags=["-DTHINGS_AND_STUFF"],
                        js_sources=["my-patches.js"],
                        new_uuid=uuid.uuid4())

Some work is performed when you first instantiate the `Patcher`, so hold on to it if you're patching multiple apps. `c_sources`, `js_sources`, `cflags`, and `new_uuid` are all optional.

Creating patches (C)
--------------------

You write C patches pretty much the same way you write C Pebble apps; the full Pebble C SDK is available at all times. The big difference is that you're working inside another app, there's no separate entrypoint or execution thread.

Instead, you get things to happen (or not happen, as the case may be) by overriding Pebble SDK calls. You do this by defining a function `<sdk_function>__patch` with the exact same signature as the SDK call it's overriding. Within this function, you can do whatever you want, including calling the original SDK function by its usual name.

For instance, want to turn the backlight on when the app starts?

    #include <pebble.h>

    void app_event_loop__patch(void) {
      light_enable(true);
      app_event_loop();
    }

Or show the BT status on screen?

    #include <pebble.h>

    TextLayer* bt_status_text;
    BluetoothConnectionHandler their_bt_status_handler;

    static void update_bluetooth_status_text(bool connected) {
        text_layer_set_text(bt_status_text, connected ? "Connected" : "Disconnected");
        layer_mark_dirty(text_layer_get_layer(bt_status_text));
    }

    static void bluetooth_callback(bool connected) {
      update_bluetooth_status_text(connected);
      if (their_bt_status_handler) their_bt_status_handler(connected);
    }

    static void setup_bluetooth_status(void) {
      bt_status_text = text_layer_create(GRect(0, 0, 144, 20));
      text_layer_set_background_color(bt_status_text, GColorClear);
      text_layer_set_text_color(bt_status_text, GColorWhite);
      update_bluetooth_status_text(bluetooth_connection_service_peek());
      bluetooth_connection_service_subscribe(bluetooth_callback);
    }

    void window_stack_push__patch(Window* window, bool animated) {
      if (!bt_status_text) setup_bluetooth_status();
      layer_add_child(window_get_root_layer(window), text_layer_get_layer(bt_status_text));
      window_stack_push(window, animated);
    }

    // Keeping our TextLayer on top, the brute-force approach
    void layer_add_child__patch(Layer* parent, Layer* child) {
      layer_add_child(parent, child);
      if (parent == window_get_root_layer(window_stack_get_top_window())) {
        layer_add_child(parent, text_layer_get_layer(bt_status_text));
      }
    }

    // They might want to use the BT connection service, too
    void bluetooth_connection_service_subscribe__patch(BluetoothConnectionHandler handler) {
      their_bt_status_handler = handler;
    }

    void bluetooth_connection_service_unsubscribe__patch(void) {
      their_bt_status_handler = NULL;
    }

Creating patches (JS)
---------------------

There's not much to JS patches - they're simply prepended to the app's existing JS (if any) in the order specified.
