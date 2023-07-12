jQuery(document).ready(function () {
    Toastify({
        text: "Welcome to Gemini-Self Protector Installer",
        duration: 3000,
        gravity: "top", // `top` or `bottom`
        position: "right", // `left`, `center` or `right`
        stopOnFocus: true, // Prevents dismissing of toast on hover
        style: {
            background: "linear-gradient(to right, #00b09b, #96c93d)",
        },
    }).showToast();
    // click on next button
    jQuery('.form-wizard-next-btn').click(function () {
        var parentFieldset = jQuery(this).parents('.wizard-fieldset');
        var currentActiveStep = jQuery(this).parents('.form-wizard').find('.form-wizard-steps .active');
        var next = jQuery(this);
        var nextWizardStep = true;

        var sensitiveValue = jQuery('#sensitiveValue').val();
        if (sensitiveValue === "" || isNaN(parseInt(sensitiveValue)) || parseInt(sensitiveValue) < 0 || parseInt(sensitiveValue) > 100) {
            parentFieldset.find('.wizard-form-error').slideDown();
            nextWizardStep = false;
        } else {
            parentFieldset.find('.wizard-form-error').slideUp();
        }

        var radioValue = jQuery('input[name="radio-mode"]:checked').val();
        if (radioValue === undefined) {
            parentFieldset.find('.wizard-form-error').slideDown();
            nextWizardStep = false;
        } else {
            parentFieldset.find('.wizard-form-error').slideUp();
        }

        var geminiAppPath = jQuery('#geminiAppPath').val();
        var regex = /^[0-9a-f]{40}\/gemini$/;

        if (regex.test(geminiAppPath)) {
            parentFieldset.find('.wizard-form-error').slideUp();
        } else {
            parentFieldset.find('.wizard-form-error').slideDown();
            nextWizardStep = false;
        }

        var password = jQuery('#pwd').val();
        var confirmPassword = jQuery('#cpwd').val();;
        var passwordRegex = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;

        if (password != "") {
            if (password === confirmPassword) {
                if (passwordRegex.test(password)) {
                    parentFieldset.find('.wizard-form-error').slideUp();
                } else {
                    parentFieldset.find('.wizard-form-error').slideDown();
                    nextWizardStep = false;
                }
            } else {
                parentFieldset.find('.wizard-form-error').slideDown();
                nextWizardStep = false;
            }
        }

        // Listen for radio button change event
        $('input[name="radio-channel"]').change(function () {
            var selectedValue = $(this).val();

            // Check if the "telegram" option is selected
            if (selectedValue === "telegram") {
                $('#telegram-form-1').show(); // Show the form inputs
                $('#telegram-form-2').show();
            } else {
                $('#telegram-form-1').hide(); // Hide the form inputs
                $('#telegram-form-2').hide();
            }
        });

        var channelValue = jQuery('input[name="radio-channel"]:checked').val();
        console.log(channelValue);
        if (channelValue === "telegram") {
            var telegramToken = jQuery('#telegram_token').val();
            var telegramChatId = jQuery('#telegram_chat_id').val();

            if (telegramToken == "" || telegramChatId == "") {
                jQuery(this).siblings(".wizard-form-error").slideDown();
                nextWizardStep = false;
            } else {
                jQuery(this).siblings(".wizard-form-error").slideUp();
            }
        }

        parentFieldset.find('.wizard-required').each(function () {
            var thisValue = jQuery(this).val();

            if (thisValue == "") {
                jQuery(this).siblings(".wizard-form-error").slideDown();
                nextWizardStep = false;
            }
            else {
                jQuery(this).siblings(".wizard-form-error").slideUp();
            }
        });
        if (nextWizardStep) {
            next.parents('.wizard-fieldset').removeClass("show", "400");
            currentActiveStep.removeClass('active').addClass('activated').next().addClass('active', "400");
            next.parents('.wizard-fieldset').next('.wizard-fieldset').addClass("show", "400");
            jQuery(document).find('.wizard-fieldset').each(function () {
                if (jQuery(this).hasClass('show')) {
                    var formAtrr = jQuery(this).attr('data-tab-content');
                    jQuery(document).find('.form-wizard-steps .form-wizard-step-item').each(function () {
                        if (jQuery(this).attr('data-attr') == formAtrr) {
                            jQuery(this).addClass('active');
                            var innerWidth = jQuery(this).innerWidth();
                            var position = jQuery(this).position();
                            jQuery(document).find('.form-wizard-step-move').css({ "left": position.left, "width": innerWidth });
                        } else {
                            jQuery(this).removeClass('active');
                        }
                    });
                }
            });
        }
    });
    //click on previous button
    jQuery('.form-wizard-previous-btn').click(function () {
        var counter = parseInt(jQuery(".wizard-counter").text());;
        var prev = jQuery(this);
        var currentActiveStep = jQuery(this).parents('.form-wizard').find('.form-wizard-steps .active');
        prev.parents('.wizard-fieldset').removeClass("show", "400");
        prev.parents('.wizard-fieldset').prev('.wizard-fieldset').addClass("show", "400");
        currentActiveStep.removeClass('active').prev().removeClass('activated').addClass('active', "400");
        jQuery(document).find('.wizard-fieldset').each(function () {
            if (jQuery(this).hasClass('show')) {
                var formAtrr = jQuery(this).attr('data-tab-content');
                jQuery(document).find('.form-wizard-steps .form-wizard-step-item').each(function () {
                    if (jQuery(this).attr('data-attr') == formAtrr) {
                        jQuery(this).addClass('active');
                        var innerWidth = jQuery(this).innerWidth();
                        var position = jQuery(this).position();
                        jQuery(document).find('.form-wizard-step-move').css({ "left": position.left, "width": innerWidth });
                    } else {
                        jQuery(this).removeClass('active');
                    }
                });
            }
        });
    });
    //click on form submit button
    jQuery(document).on("click", ".form-wizard .form-wizard-submit", function () {
        var parentFieldset = jQuery(this).parents('.wizard-fieldset');
        var currentActiveStep = jQuery(this).parents('.form-wizard').find('.form-wizard-steps .active');
        parentFieldset.find('.wizard-required').each(function () {
            var thisValue = jQuery(this).val();
            if (thisValue == "") {
                jQuery(this).siblings(".wizard-form-error").slideDown();
            }
            else {
                console.log("Oki")
                jQuery(this).siblings(".wizard-form-error").slideUp();
            }
        });
    });
    // focus on input field check empty or not
    jQuery(".form-control").on('focus', function () {
        var tmpThis = jQuery(this).val();
        if (tmpThis == '') {
            jQuery(this).parent().addClass("focus-input");
        }
        else if (tmpThis != '') {
            jQuery(this).parent().addClass("focus-input");
        }
    }).on('blur', function () {
        var tmpThis = jQuery(this).val();
        if (tmpThis == '') {
            jQuery(this).parent().removeClass("focus-input");
            jQuery(this).siblings('.wizard-form-error').slideDown("3000");
        }
        else if (tmpThis != '') {
            jQuery(this).parent().addClass("focus-input");
            jQuery(this).siblings('.wizard-form-error').slideUp("3000");
        }
    });

    $("#predict-server").click(function (event) {
        $("#loading-spinner").show();
        // Get the input value
        var serverValue = $("#predictServerValue").val();
        var keyAuthValue = $("#keyAuthServerValue").val();
        // Make the POST request
        $.ajax({
            url: serverValue + '/predict',
            type: "POST",
            headers: {
                "Authorization": keyAuthValue
            },
            contentType: "application/json",
            data: JSON.stringify({ data: "healthcheck" }),
            success: function (response) {
                // Handle the success response
                if (response.accuracy) {
                    Toastify({
                        text: "Connected to this predict server",
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
                        text: "Cannot connect to this predict server",
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
            error: function (error) {
                // Handle the error response
                Toastify({
                    text: "Cannot connect to this predict server",
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
                // Hide the loading spinner when the request is complete
                $("#loading-spinner").hide();
            }
        });
    });
});