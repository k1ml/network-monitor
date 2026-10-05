// const wsUri = "ws://127.0.0.1/";
const num_items_per_bar = 40;
let target_to_bars = [];
let charts = [];
let time_axis = Array(num_items_per_bar);

function sparkbar_id(index)
{
    return "target_bars_" + index;
}

function on_websocket_message(message)
{
    const current_time = new Date();
    var current_time_str = (
        current_time.getHours() + ":" +
        current_time.getMinutes() + ":" +
        current_time.getSeconds()
    );
    time_axis.shift(1);
    time_axis.push(current_time_str);

    var json_data = JSON.parse(message);
    if (json_data !== undefined && json_data !== null && json_data.constructor == Object)
    {
        if ('hosts_table' in json_data)
        {
            document.getElementById('hosts_table').innerHTML = json_data['hosts_table'];
            document.getElementById('box_alert_warning').hidden = true;
        }

        if ('hosts_data' in json_data)
        {
            var counter = 0;
            for (const [name, latency] of json_data['hosts_data']) {
                if (!Object.hasOwn(target_to_bars, name))
                {
                    var new_bars = target_to_bars[name] = (
                        Array(num_items_per_bar).fill(0, 0, num_items_per_bar)
                    );

                    // Append a new <div><canvas> to the front_row div. This is not
                    // necessarily the div that will be used for this target!
                    // They will be used in the order that they appear in hosts_data.
                    // The new one is called target_bars_<count> where <count> is the
                    // number of existing elements, not the current counter, because
                    // they should be maintained in numeric order.
                    var new_div = document.createElement("div");
                    new_div.setAttribute("class", "col-md-3 mt-3");
                    var new_canvas = document.createElement("canvas");
                    var new_index = charts.length;
                    new_canvas.setAttribute("id", sparkbar_id(new_index));
                    new_div.appendChild(new_canvas);
                    document.getElementById("front_row").appendChild(new_div);
                    charts.push(draw_sparkbar(sparkbar_id(new_index), new_bars));
                }

                var bars = target_to_bars[name];
                bars.splice(0, 1); // remove first element
                bars.push(latency); // append new value
                var chart = charts[counter];
                chart.data.datasets[0].data = bars;
                chart.data.labels = time_axis;
                chart.options.plugins.title.text = name;
                chart.update('none');
                counter++;
            }
        }
    }
}

function draw_sparkbar(name, values)
{
    const ctx = document.getElementById(name);
    return new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Latency',
                data: values,
                borderWidth: 1
            }]
        },
        options: {
            scales: {
                y: {
                    beginAtZero: true
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Initial title'
                },
                legend: {
                    display: false
                }
            }
        }
    });
}

function init_websocket() {
    var websocket = new WebSocket(wsUri);
    window.ping_interval_handle = null;
    websocket.addEventListener("error", (event) => {
        console.log(event);
        document.getElementById('box_alert_warning').innerHTML = event.nessage;
        document.getElementById('box_alert_warning').hidden = false;
    });
    websocket.addEventListener("close", (event) => {
        console.log("DISCONNECTED: " + event);
        document.getElementById('box_alert_warning').innerHTML = (
            "Error " + event.code + ": " + event.reason + ". Will try again in 1 second."
        );
        document.getElementById('box_alert_warning').hidden = false;
        // Try to reconnect in 1 second:
        websocket = null; // avoid leaking reference
        if (window.ping_interval_handle !== null)
        {
            clearInterval(window.ping_interval_handle);
        }
        setTimeout(init_websocket, 1000);
    });
    websocket.addEventListener("open", () => {
        console.log("CONNECTED");
        window.ping_interval_handle = setInterval(() => {
        console.log(`SENT: ping: ${counter}`);
        websocket.send("ping");
    }, 1000);
    });
    var counter = 1;
    websocket.addEventListener("message", (e) => {
        var message = e.data;
        console.log(`RECEIVED: ${counter}: ${message}`);
        counter++;
        on_websocket_message(message);
    });
}

init_websocket();
