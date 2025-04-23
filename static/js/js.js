 $(document).ready(function() {
        // Triggering the counter animation when the statistics section comes into view
     let counterTriggered = false;
     $(window).on('scroll', function() {
         const statisticsOffset = $('#statistics').offset().top;
         const scrollY = $(this).scrollTop() + $(this).height();
         if (scrollY > statisticsOffset && !counterTriggered) {
                $('.counter').each(function() {
                    const $this = $(this);
                    const countTo = $this.data('count');

                    $({ countNum: $this.text() }).animate({
                        countNum: countTo
                    },
                    {
                        duration: 2000, // duration of animation in milliseconds
                        easing: 'swing', // easing function
                        step: function() {
                            $this.text(Math.floor(this.countNum)); // updating the text with the current value
                        },
                        complete: function() {
                            $this.text(this.countNum + '+'); // ensure the final value is followed by a '+' sign
                        }
                    });
                });
                counterTriggered = true; // Prevent multiple triggers
            }
        });
    });

    // Expandable FAQ Functionality
    function toggleFAQ(faqId, element) {
        var faqContent = document.getElementById(faqId);
        if (faqContent.style.display === "none") {
            faqContent.style.display = "block"; // Show content
            element.querySelector('.faq-toggle').textContent = '-'; // Change to minus sign
        } else {
            faqContent.style.display = "none"; // Hide content
            element.querySelector('.faq-toggle').textContent = '+'; // Change to plus sign
        }
    }


