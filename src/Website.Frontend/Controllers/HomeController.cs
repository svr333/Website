using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Website.Frontend.Models;

namespace Website.Frontend.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        public HomeController(ILogger<HomeController> logger)
        {
            _logger = logger;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [Authorize(AuthenticationSchemes = "Discord")]
        public IActionResult Secret()
        {
            var id = User.Claims.First(x => x.Type == ClaimTypes.NameIdentifier).Value;
            var username = User.Claims.First(x => x.Type == ClaimTypes.Name).Value;

            if (id != "202095042372829184")
            {
                return Unauthorized();
            }

            return View();
        }

        public IActionResult DiscordAuthFailed()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
