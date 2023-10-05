jQuery(document).ready(function () {
    Toastify({
        text: "Welcome to Gemin Self-Protector Installer",
        duration: 3000,
        gravity: "top", // `top` or `bottom`
        position: "right", // `left`, `center` or `right`
        stopOnFocus: true, // Prevents dismissing of toast on hover
        style: {
            background: "linear-gradient(to right, #00b09b, #96c93d)",
        },
    }).showToast();

    var passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
    const rootUrl = location.protocol + '//' + location.host + '/';
    const rootUrlElement = document.getElementById("rootUrl");
    rootUrlElement.innerHTML = rootUrl;

    // Initially
    $('#form-sensitive').show();
    $('#form-g-wvd').show();
    $('#form-g-key').show();
    $('#g-wvd-serve-value').attr('required', 'required');
    $('#g-serve-key-value').attr('required', 'required');
    // Listen for using G-WVD serve
    $('#checkbox-g-wvd').change(function () {
        if ($(this).is(':checked')) {
            $('#form-sensitive').show();
            $('#form-g-wvd').show();
            $('#form-g-key').show();
            $('#g-wvd-serve-value').attr('required', 'required');
            $('#g-serve-key-value').attr('required', 'required');
        } else {
            $('#form-sensitive').hide();
            $('#form-g-wvd').hide();
            $('#form-g-key').hide();
            $('#g-wvd-serve-value').removeAttr('required');
            $('#g-serve-key-value').removeAttr('required');
        }
    });

    // Listen for notification channel
    $('input[name="notification-channel"]').change(function () {
        const selectedValue = $(this).val();

        if (selectedValue === "telegram") {
            $('#form-telegram-1').show();
            $('#form-telegram-2').show();
            $('#form-mattermost').hide();
            $('#form-slack').hide();
            $('#telegram-token-value').attr('required', 'required');
            $('#telegram-chat-id-value').attr('required', 'required');
            $('#mattermost-webhook-value').removeAttr('required');
            $('#slack-webhook-value').removeAttr('required');
        } else if (selectedValue === "mattermost") {
            $('#form-telegram-1').hide();
            $('#form-telegram-2').hide();
            $('#form-mattermost').show();
            $('#form-slack').hide();
            $('#telegram-token-value').removeAttr('required');
            $('#telegram-chat-id-value').removeAttr('required');
            $('#mattermost-webhook-value').attr('required', 'required');
            $('#slack-webhook-value').removeAttr('required');
        } else if (selectedValue === "slack") {
            $('#form-telegram-1').hide();
            $('#form-telegram-2').hide();
            $('#form-mattermost').hide();
            $('#form-slack').show();
            $('#telegram-token-value').removeAttr('required');
            $('#telegram-chat-id-value').removeAttr('required');
            $('#mattermost-webhook-value').removeAttr('required');
            $('#slack-webhook-value').attr('required', 'required');
        } else {
            $('#form-telegram-1').hide();
            $('#form-telegram-2').hide();
            $('#form-mattermost').hide();
            $('#form-slack').hide();
            $('#telegram-token-value').removeAttr('required');
            $('#telegram-chat-id-value').removeAttr('required');
            $('#mattermost-webhook-value').removeAttr('required');
            $('#slack-webhook-value').removeAttr('required');
        }
    });

    // Listen btn check connection click
    $("#g-wvd-check-connection").click(function (event) {
        // Get the input value
        var gWVDServeValue = $("#g-wvd-serve-value").val();
        var gServeKeyValue = $("#g-serve-key-value").val();
        // Make the POST request
        $.ajax({
            url: gWVDServeValue + '/ping',
            type: "GET",
            headers: {
                "Authorization": gServeKeyValue
            },
            contentType: "application/json",
            success: function (response, textStatus, jqXHR) {
                // Handle the success response
                if (jqXHR.status === 200) {
                    Toastify({
                        text: "Connected to G-WVD serve",
                        duration: 3000,
                        gravity: "top", // `top` or `bottom`
                        position: "right", // `left`, `center` or `right`
                        stopOnFocus: true, // Prevents dismissing of toast on hover
                        style: {
                            background: "linear-gradient(to right, #00b09b, #96c93d)",
                        },
                    }).showToast();
                } else {
                    Toastify({
                        text: "Cannot connect to G-WVD serve",
                        duration: 3000,
                        gravity: "top", // `top` or `bottom`
                        position: "right", // `left`, `center` or `right`
                        stopOnFocus: true, // Prevents dismissing of toast on hover
                        style: {
                            background: "linear-gradient(to right, rgb(255, 95, 109), rgb(255, 195, 113))",
                        },
                    }).showToast();
                }
            },
            error: function (jqXHR, textStatus, errorThrown) {
                // Handle the error response
                Toastify({
                    text: "Cannot connect to G-WVD serve",
                    duration: 3000,
                    gravity: "top", // `top` or `bottom`
                    position: "right", // `left`, `center` or `right`
                    stopOnFocus: true, // Prevents dismissing of toast on hover
                    style: {
                        background: "linear-gradient(to right, rgb(255, 95, 109), rgb(255, 195, 113))",
                    },
                }).showToast();
            },
            complete: function () {
                //
            }
        });
    });

    $('#install').submit(function (e) {
        e.preventDefault();
        $('#submit').prop('disabled', true);
        let submit = false;
        const formData = $(this).serializeArray().reduce(function (obj, item) {
            obj[item.name] = item.value;
            return obj;
        }, {});

        const dashboardPwdValue = formData['dashboard-pwd-value'];
        const dashboardCpwdValue = formData['dashboard-cpwd-value'];

        if (dashboardPwdValue === dashboardCpwdValue) {
            if (passwordPattern.test(dashboardPwdValue)) {
                submit = true;
            } else {
                Toastify({
                    text: "Password dose not match policy",
                    duration: 3000,
                    gravity: "top", // `top` or `bottom`
                    position: "right", // `left`, `center` or `right`
                    stopOnFocus: true, // Prevents dismissing of toast on hover
                    style: {
                        background: "linear-gradient(to right, rgb(255, 95, 109), rgb(255, 195, 113))",
                    },
                }).showToast();
            }
        } else {
            submit = false;
            Toastify({
                text: "Password and Confirm Password dose not same",
                duration: 3000,
                gravity: "top", // `top` or `bottom`
                position: "right", // `left`, `center` or `right`
                stopOnFocus: true, // Prevents dismissing of toast on hover
                style: {
                    background: "linear-gradient(to right, rgb(255, 95, 109), rgb(255, 195, 113))",
                },
            }).showToast();
        }

        if (submit) {
            $.ajax({
                type: "POST",
                url: installEndpoint,
                data: JSON.stringify(formData), // Convert the JSON object to a string
                contentType: "application/json; charset=utf-8",
                dataType: "json",
                success: function (response, textStatus, jqXHR) {
                    if (jqXHR.status === 200) {
                        Toastify({
                            text: "Install Gemini Self-Protector Successed",
                            duration: 3000,
                            gravity: "top", // `top` or `bottom`
                            position: "right", // `left`, `center` or `right`
                            stopOnFocus: true, // Prevents dismissing of toast on hover
                            style: {
                                background: "linear-gradient(to right, #00b09b, #96c93d)",
                            },
                        }).showToast();
                        window.location.href = 'login';
                    } else {
                        Toastify({
                            text: "Install Gemini Self-Protector Failed. Please check your log.",
                            duration: 3000,
                            gravity: "top", // `top` or `bottom`
                            position: "right", // `left`, `center` or `right`
                            stopOnFocus: true, // Prevents dismissing of toast on hover
                            style: {
                                background: "linear-gradient(to right, rgb(255, 95, 109), rgb(255, 195, 113))",
                            },
                        }).showToast();
                    }
                },
                error: function (jqXHR, textStatus, errorThrown) {
                    // Handle any errors here
                    console.error("Error:", textStatus, errorThrown);
                    $('#submit').removeAttr('disable', 'disable');
                },
                complete: function () {
                    // Re-enable the button after the request is complete
                    $('#submit').prop('disabled', false);
                }
            });
        } else {
            Toastify({
                text: "Cannot submit this install form",
                duration: 3000,
                gravity: "top", // `top` or `bottom`
                position: "right", // `left`, `center` or `right`
                stopOnFocus: true, // Prevents dismissing of toast on hover
                style: {
                    background: "linear-gradient(to right, rgb(255, 95, 109), rgb(255, 195, 113))",
                },
            }).showToast();
        }
    });
});